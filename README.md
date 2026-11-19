# container-image-layer-deduplicator

分析容器镜像层内容并规划跨镜像去重与安全复用。

**这是一个静态规划工具**：它只读取镜像清单与本地层 tar 内容，输出可复用的
层/文件范围、预计节省空间、冲突原因和不能安全复用的项目。它不会修改、重打包
或写出任何镜像数据，所有结论仅供后续去重实施参考。

## 背景

多个服务镜像包含大量重复文件和近似重复层。直接按压缩包摘要比较会漏掉跨镜像
复用（同一层用不同压缩参数得到不同摘要），只按文件名又可能把内容不同的文件
错误合并。本工具按**文件内容**建立安全的内容索引：

- 层级复用以 diffID（未压缩层摘要）为准，并校验本地 tar 的实际摘要；
- 文件级复用以内容 sha256 为准，而不是文件名；
- 同名不同内容记为冲突，绝不合并。

## 输入

JSON 清单，描述每个镜像的层（diffID、压缩摘要、压缩大小、本地 tar 路径）：

```json
{
  "images": [
    {
      "name": "app:1.0",
      "layers": [
        {
          "diff_id": "sha256:...",
          "compressed_digest": "sha256:...",
          "compressed_size": 12345,
          "tar_path": "layers/app-layer-0.tar"
        }
      ]
    }
  ]
}
```

## 使用

```bash
python -m oci_layer_analyzer manifest.json   # 输出 JSON 规划报告
python -m unittest                           # 运行测试
```

要求 Python 3.8+，仅使用标准库。

## 输出

每个镜像一份报告：

- `reusable_layers`：可整体复用的层（diffID 相同），含来源镜像与节省字节数；
- `reusable_files`：可共享内容的文件（内容摘要相同），含权威副本位置；
- `estimated_savings_bytes`：该镜像预计可节省的空间；
- `conflicts`：同名不同内容的路径及冲突原因，不能按名合并；
- `unsafe_items`：不能安全复用的项目（路径穿越、悬空缺目标的硬链接等）；
- `unusable_layers`：损坏的 tar 或 diffID 校验失败的层及原因；
- `whiteouts` / `hardlink_notes`：whiteout 与硬链接的语义记录。

## 安全规则

- 普通文件、目录、符号链接、硬链接、whiteout（`.wh.` 与 `.wh..wh..opq`）
  都会被识别；只有普通文件的内容参与去重；
- 路径穿越或绝对路径的条目只记录为风险，绝不参与索引与去重；
- 硬链接只共享底层内容块，硬链接语义不同的文件不会被强行合并成同一链接组；
- 损坏的 tar 不会导致分析崩溃，整层标记为不可用并记录原因。

## 代码结构

- `oci_layer_analyzer/models.py`：清单、层与文件条目的数据模型；
- `oci_layer_analyzer/tarindex.py`：安全的 tar 解析与内容索引；
- `oci_layer_analyzer/analyzer.py`：跨镜像复用规划与冲突检测；
- `oci_layer_analyzer/__main__.py`：命令行入口；
- `tests/test_analyzer.py`：覆盖完全相同层、文件级重复、whiteout、损坏 tar、
  同名异内容、路径穿越、多镜像共享、硬链接语义等场景。
