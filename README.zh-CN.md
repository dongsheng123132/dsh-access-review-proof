# dsh-access-review-proof

作者 / 维护者：He Fangsheng (贺方升 / 贺去病; Dosen)· [hequbing.com](https://www.hequbing.com)

这是一个离线、确定性的 DSH 证据层，只回答一个窄问题：**显式提供的权限复核活动，是否覆盖全部已声明 entitlement、满足风险分级复核，并把每个保留/撤销决定闭合到新鲜的复核后清单？**

同一个无界面核心同时提供 DSH bundle、独立 MCP stdio、JavaScript API 和 CLI；报告脱敏、内容寻址，并在写后回读。

## 互补边界

Microsoft Entra access reviews 用于治理和再认证 group、application、access package 与 role 权限。本插件只核验 supplied structured evidence，不是身份治理平台。

- `dsh-principal-binding-proof` 核验证据链绑定的 authority/principal；
- `dsh-policy-waiver-proof` 核验声明的策略例外；
- `dsh-break-glass-settlement-proof` 核验单次紧急访问会话闭合；
- 本插件核验一份已声明 entitlement 清单的分阶段决定、keep/revoke 落地闭合和复核后 snapshot。

它不会审批、保留或撤销权限，不认证回执、不查询线上身份系统，也不证明 supplied inventory 包含现实中的全部权限。closure 和 snapshot 仍只是待外部认证的显式证据。

## 核验项

- review 起止、due date、closure、snapshot、evaluation 时序；
- 已声明 entitlement 集合的精确覆盖；
- 按风险要求的 stage 数与连续有序决定；
- 配置为高风险时的 reviewer 独立性和禁止自审；
- decisions、closures、snapshot 的同一 review binding；
- 每个 entitlement 恰好一条复核完成后的 closure；
- 最终 `keep`/`revoke` 与 `active`/`revoked` 一致；
- 撤销决定必须有非零 application receipt；
- snapshot 中 active/revoked 对全部已声明权限精确分区；
- 观察者多样性、证据新鲜度；
- 拒绝秘密/raw 字段、workspace 限界、symlink 防护、内容寻址回读。

```bash
npm test
npm run check
node bin/dsh-access-review-proof.mjs verify examples/closed.json
dsh plugin --profile <profile> add github:dongsheng123132/dsh-access-review-proof#<commit>
```

DSH 工具是 `dsh_access_review_inspect`、`dsh_access_review_verify`；MCP 工具是 `access_review_inspect`、`access_review_verify`。完整 manifest 见 [`examples/closed.json`](examples/closed.json)。禁止放账户名、密钥、token、原始身份导出或业务正文。

规范来源：[Microsoft Entra access reviews overview](https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview)、[plan access reviews](https://learn.microsoft.com/en-us/entra/id-governance/deploy-access-reviews)、[complete access review](https://learn.microsoft.com/en-us/entra/id-governance/complete-access-review)。
