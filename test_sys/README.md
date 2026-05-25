# test_sys

`test_sys/run_all.sh` 是 EdgeSec-Pi 的批次測試入口，會把每個測試集合分開執行，並將輸出寫成 log 檔。

## 使用方式

```bash
./test_sys/run_all.sh
```

等同於：

```bash
./test_sys/run_all.sh quick
```

## 模式

| 模式 | 用途 | 會碰到真服務嗎 |
|------|------|----------------|
| `quick` | 日常開發檢查：後端測試、前端 lint/build。 | 不會 |
| `env` | 檢查本機服務是否有跑：Bridge、Dashboard、LM Studio、Wazuh、MCP。 | 會 |
| `release` | 發版前檢查：`quick` 加上品質閘門與 mock eval。 | 不會 |
| `full` | 完整驗證：`release` 加上服務狀態、真 LM Studio model 測試與真 Wazuh E2E。 | 會 |
| `manual` | 顯示互動式手動測試入口。 | 依手動測試而定 |

## Log 位置

每次執行會建立一個新資料夾：

```text
test_sys/logs/YYYYMMDD-HHMMSS/
```

裡面會有：

- `summary.txt`：總結哪個集合通過、哪個失敗。
- `01-*.log`、`02-*.log`：各集合完整輸出。

## 建議順序

日常改程式：

```bash
./test_sys/run_all.sh quick
```

準備發版：

```bash
./test_sys/run_all.sh release
```

要驗證真 Wazuh 與真 LM Studio：

```bash
./test_sys/run_all.sh full
```

只想確認服務有沒有開：

```bash
./test_sys/run_all.sh env
```
