use anyhow::Result;
use http::Request;
use rand::Rng;
use tracing::debug;

/// 通过 HTTP/3 POST /auth 进行 Hysteria2 认证
/// 成功状态码: 233
/// `down_bps`: 客户端下行带宽 (bytes/sec)，用于服务端 Brutal CC，0 表示不限速
pub async fn authenticate(conn: &quinn::Connection, password: &str, down_bps: u64) -> Result<()> {
    // 构建 h3 连接
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

    // 驱动 h3 连接（在后台运行）
    let drive = tokio::spawn(async move {
        let _err = futures_lite::future::poll_fn(|cx| driver.poll_close(cx)).await;
        tracing::debug!("h3 driver closed");
    });

    // 生成随机 padding（在 await 之前完成，避免 Send 问题）
    let padding = {
        let mut rng = rand::thread_rng();
        let padding_len: usize = rng.gen_range(64..256);
        (0..padding_len)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect::<String>()
    };

    // 构建 POST /auth 请求
    let req = Request::post("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", down_bps.to_string())
        .header("Hysteria-Padding", &padding)
        .body(())?;

    let mut req_stream = send_request.send_request(req).await?;
    req_stream.finish().await?;

    let resp = req_stream.recv_response().await?;
    let status = resp.status().as_u16();

    debug!(status = status, "Hysteria2 auth response");

    // 关闭 h3 连接
    drop(send_request);
    drive.abort();

    if status != 233 {
        anyhow::bail!("hysteria2 auth failed: status {}", status);
    }

    Ok(())
}
