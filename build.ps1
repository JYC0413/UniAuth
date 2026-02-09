# 1. 设置环境变量（仅对当前会话有效，不会污染系统环境）
$env:GOOS = "linux"
$env:GOARCH = "amd64"

Write-Host "--- 开始交叉编译 ---" -ForegroundColor Cyan
Write-Host "目标平台: $env:GOOS / $env:GOARCH"

# 2. 执行编译命令
# -o 指定输出文件名，main.go 是源文件
go build -o uniauth main.go

# 3. 检查上一步命令的执行结果
if ($LASTEXITCODE -eq 0) {
    Write-Host "编译成功！输出文件: uniauth" -ForegroundColor Green
} else {
    Write-Host "编译失败，请检查代码错误或 Go 环境设置。" -ForegroundColor Red
    exit $LASTEXITCODE
}