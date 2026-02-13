#!/bin/bash
# OpenWorld Linux 部署脚本
# 用法: sudo ./install.sh [config_path]

set -e

BINARY="/usr/local/bin/openworld"
SERVICE_FILE="/etc/systemd/system/openworld.service"
CONFIG_DIR="/etc/openworld"
LOG_DIR="/var/log/openworld"
CONFIG_SRC="${1:-}"

echo "=== OpenWorld Linux 安装 ==="

# 1. 创建用户
if ! id -u openworld &>/dev/null; then
    useradd -r -s /sbin/nologin -d /etc/openworld openworld
    echo "✅ 用户 openworld 已创建"
fi

# 2. 复制二进制
if [ -f "target/release/openworld" ]; then
    cp target/release/openworld "$BINARY"
    chmod 755 "$BINARY"
    echo "✅ 二进制已安装到 $BINARY"
elif [ -f "openworld" ]; then
    cp openworld "$BINARY"
    chmod 755 "$BINARY"
    echo "✅ 二进制已安装到 $BINARY"
else
    echo "❌ 未找到 openworld 二进制文件"
    echo "   请先运行: cargo build --release"
    exit 1
fi

# 3. 创建目录
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chown -R openworld:openworld "$CONFIG_DIR" "$LOG_DIR"

# 4. 复制配置
if [ -n "$CONFIG_SRC" ] && [ -f "$CONFIG_SRC" ]; then
    cp "$CONFIG_SRC" "$CONFIG_DIR/config.yaml"
    chown openworld:openworld "$CONFIG_DIR/config.yaml"
    echo "✅ 配置已复制到 $CONFIG_DIR/config.yaml"
elif [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo "⚠️  请手动创建配置文件: $CONFIG_DIR/config.yaml"
fi

# 5. 安装 systemd service
cp deploy/openworld.service "$SERVICE_FILE"
systemctl daemon-reload
echo "✅ systemd 服务已安装"

# 6. 设置 capabilities（避免以 root 运行）
setcap 'cap_net_admin,cap_net_bind_service,cap_net_raw+ep' "$BINARY" 2>/dev/null || \
    echo "⚠️  setcap 失败（可能需要 libcap2-bin），服务仍可通过 systemd 获取权限"

echo ""
echo "=== 安装完成 ==="
echo ""
echo "常用命令:"
echo "  启动:   systemctl start openworld"
echo "  停止:   systemctl stop openworld"
echo "  状态:   systemctl status openworld"
echo "  日志:   journalctl -u openworld -f"
echo "  自启:   systemctl enable openworld"
echo "  禁自启: systemctl disable openworld"
echo ""
