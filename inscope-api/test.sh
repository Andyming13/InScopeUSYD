#!/bin/bash
set -e

API="http://localhost:8787/api/v1/auth"

echo "请输入测试邮箱 (比如 test@example.com): "
read EMAIL

# Step 1: 请求验证码
echo "[1] 请求验证码..."
curl -s -X POST "$API/request-code" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\"}" | jq .

echo ""
echo "⚠️ 请查看后端日志，找到 [DEV MAIL] 打印的验证码"
echo "请输入你收到的验证码: "
read CODE

# Step 2: 验证邮箱，获取 registration_token
echo "[2] 验证验证码..."
VERIFY=$(curl -s -X POST "$API/verify-code" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"code\":\"$CODE\"}")

echo $VERIFY | jq .

TOKEN=$(echo $VERIFY | jq -r '.registration_token')

if [ "$TOKEN" = "null" ]; then
  echo "❌ 验证失败，没有拿到 registration_token"
  exit 1
fi

echo ""
echo "✅ 已获取 registration_token: $TOKEN"

# Step 3: 输入用户名 & 密码
echo "请输入用户名:"
read USERNAME
echo "请输入密码 (至少 8 位，含大小写/数字/符号):"
read -s PASSWORD

# Step 4: 注册
echo "[3] 注册中..."
curl -s -X POST "$API/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" | jq .