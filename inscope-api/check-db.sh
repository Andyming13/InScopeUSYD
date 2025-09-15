#!/bin/bash
set -e

# 从 .env 里读取 DATABASE_URL
DB_URL=$(grep ^DATABASE_URL .env | cut -d '=' -f2-)

if [ -z "$DB_URL" ]; then
  echo "❌ 没有在 .env 里找到 DATABASE_URL"
  exit 1
fi

echo "尝试连接数据库..."
PGCONNECT_TIMEOUT=10 psql "$DB_URL" -c "select now(), current_user, inet_server_addr();"