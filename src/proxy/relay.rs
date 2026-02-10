use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// 双向数据转发
pub async fn relay<A, B>(mut a: A, mut b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_to_b, b_to_a) = tokio::io::copy_bidirectional(&mut a, &mut b).await?;
    debug!("relay finished: client->remote {}B, remote->client {}B", a_to_b, b_to_a);
    Ok((a_to_b, b_to_a))
}
