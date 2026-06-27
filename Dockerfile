# 多阶段构建：构建阶段
FROM golang:alpine AS builder

# 强制启用 Go 自动前滚，允许 go.mod 要求的更高版本自动下载 toolchain
# 主要是防止 CI 里忘了更新这个 Dockerfile
ENV GOTOOLCHAIN=auto

# 设置工作目录
WORKDIR /app

# 复制go.mod和go.sum
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建二进制文件
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o mosdns main.go

# 运行阶段
FROM alpine:latest

# 安装ca-certificates（如果需要）
RUN apk --no-cache add ca-certificates curl

# 设置工作目录
WORKDIR /root/

# 从构建阶段复制二进制
COPY --from=builder /app/mosdns .

# 暴露DNS端口
EXPOSE 53/udp 53/tcp

# 运行二进制
ENTRYPOINT ["/root/mosdns"]
CMD ["start"]