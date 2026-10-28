//! 指标识别规则：key 正则 → 类别/单位/聚合方式。环境自适应：存在才启用。
//! 内置规则已按真实环境校准（Zabbix 7.4 Linux 模板 + Zabbix 6.0 SNMP 模板：
//! SNMP 的 key 形如 system.cpu.util[snmp,0]、vfs.fs.used[hrStorageUsed.1]、
//! net.if.in[ifHCInOctets.1] 等，通过前缀+OID-index 归一化，与 Agent 格式统一归类）。

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggKind {
    /// 利用率：当前/avg/max/min，参与主表与评分
    Util,
    /// 原始值：当前/avg/max/min，进明细
    Raw,
    /// 事件：区间内次数/状态
    Event,
}

#[derive(Debug, Clone)]
pub struct MetricRule {
    pub id: String,
    pub pattern: String,
    pub label: String,
    pub unit: String,
    pub kind: AggKind,
}

pub struct CompiledRules {
    rules: Vec<(Regex, MetricRule)>,
}

/// 拆分 SNMP OID 形式的 [oidName.index] 后缀：ifHCInOctets.1 → ("ifHCInOctets", "1")
fn split_snmp_oid_index(s: &str) -> Option<(&str, &str)> {
    let pos = s.rfind('.')?;
    let oid = &s[..pos];
    let idx = &s[pos + 1..];
    if idx.is_empty() || !idx.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((oid, idx))
}

/// 从 key 中提取挂载点/实例名：
/// - Agent 格式：vfs.fs.dependent.size[/data,pused] → /data
/// - SNMP 格式：vfs.fs.used[hrStorageUsed.1] → snmp1（多分区按索引归并）
pub fn mount_of(key: &str) -> Option<String> {
    let start = key.find('[')?;
    let rest = &key[start + 1..];
    let end = rest.find([',', ']']).unwrap_or(rest.len());
    let raw = rest[..end].trim_matches(|c| c == '"' || c == '\'').to_string();

    if let Some((oid, idx)) = split_snmp_oid_index(&raw) {
        if oid.starts_with("hrStorage") || oid.starts_with("dsk") || oid.starts_with("diskIO") {
            return Some(format!("snmp{idx}"));
        }
    }
    Some(raw)
}

/// 从 key 中提取网卡名：
/// - Agent 格式：net.if.in["ens3",errors] → ens3
/// - SNMP 格式：net.if.in[ifHCInOctets.1] → if1（同块网卡的多指标归并到同一名）
pub fn ifname_of(key: &str) -> Option<String> {
    let start = key.find('[')?;
    let rest = &key[start + 1..];
    let end = rest.find([',', ']']).unwrap_or(rest.len());
    let raw = rest[..end].trim_matches(|c| c == '"' || c == '\'').to_string();

    if let Some((oid, idx)) = split_snmp_oid_index(&raw) {
        if oid.starts_with("if") {
            return Some(format!("if{idx}"));
        }
    }
    Some(raw)
}

pub fn builtin_rules() -> Vec<MetricRule> {
    use AggKind::*;
    let m = |id: &str, pattern: &str, label: &str, unit: &str, kind: AggKind| MetricRule {
        id: id.into(),
        pattern: pattern.into(),
        label: label.into(),
        unit: unit.into(),
        kind,
    };
    vec![
        // ---- 基础资源 ----
        // CPU 利用率：Agent `system.cpu.util` / `system.cpu.util[]`
        //             Linux SNMP `system.cpu.util[snmp]` / `system.cpu.util[snmp,N]`
        //             Windows SNMP `system.cpu.util`（无参，与 Agent 同名）
        m("cpu_util", r"^system\.cpu\.util(\[\])?$|^system\.cpu\.util\[snmp(,[0-9]+)?\]$", "CPU 利用率", "%", Util),

        // 负载：Agent `system.cpu.load[all|percpu,avgN]` / SNMP `system.cpu.load.avgN[laLoad.N]`
        m("load1", r"^system\.cpu\.load\[(all|percpu),avg1\]$|^system\.cpu\.load\.avg1\[laLoad\.[0-9]+\]$", "1 分钟负载", "", Raw),
        m("load5", r"^system\.cpu\.load\[(all|percpu),avg5\]$|^system\.cpu\.load\.avg5\[laLoad\.[0-9]+\]$", "5 分钟负载", "", Raw),
        m("load15", r"^system\.cpu\.load\[(all|percpu),avg15\]$|^system\.cpu\.load\.avg15\[laLoad\.[0-9]+\]$", "15 分钟负载", "", Raw),

        // CPU 核数
        m("cpu_num", r"^system\.cpu\.num$|^system\.cpu\.num\[snmp\]$", "CPU 核数", "", Raw),

        // 内存利用率：Agent `vm.memory.util` / `vm.memory.utilization`
        //              Linux SNMP `vm.memory.util[snmp]`
        //              Windows SNMP `vm.memory.util[memoryUsedPercentage,N]`
        m("mem_util", r"^vm\.memory\.(util|utilization)$|^vm\.memory\.util\[(snmp|memoryUsedPercentage(,[0-9]+)?)\]$", "内存利用率", "%", Util),
        m("mem_pavail", r"^vm\.memory\.size\[pavailable\]$", "内存可用%(取反)", "%", Util),
        m("mem_total", r"^vm\.memory\.size\[total\]$|^vm\.memory\.total\[memTotalReal\.0\]$|^vm\.memory\.total\[hrStorageSize\.[0-9]+\]$", "内存总量", "B", Raw),

        // swap
        m("swap_util", r"^system\.swap\.(util|pused)$", "swap 利用率", "%", Util),
        m("swap_pfree", r"^system\.swap\.size\[[^\]]*,pfree\]$|^system\.swap\.pfree\[snmp\]$", "swap 空闲%(取反)", "%", Util),

        // uptime：Agent `system.uptime` / SNMP `system.hw.uptime[hrSystemUptime.0]` 或 `system.net.uptime[sysUpTime.0]`
        m("uptime", r"^system\.uptime$|^system\.(hw|net)\.uptime\[(hrSystemUptime\.0|sysUpTime\.0)\]$", "运行时长", "s", Raw),
        m("boottime", r"^system\.boottime$", "启动时间", "unixtime", Raw),

        // 磁盘 - Agent（dependent / 老两种格式）+ SNMP hrStorage
        m("disk_pused", r"^vfs\.fs\.(dependent\.)?size\[[^\]]*,pused\]$", "分区空间%", "%", Util),
        m("disk_pused_old", r"^vfs\.fs\.pused\[", "分区空间%(老)", "%", Util),
        m("disk_used", r"^vfs\.fs\.(dependent\.)?size\[[^\]]*,used\]$|^vfs\.fs\.used\[hrStorageUsed\.[0-9]+\]$", "分区已用", "B", Raw),
        m("disk_total", r"^vfs\.fs\.(dependent\.)?size\[[^\]]*,total\]$|^vfs\.fs\.total\[hrStorageSize\.[0-9]+\]$", "分区总量", "B", Raw),
        m("inode_pused", r"^vfs\.fs\.(dependent\.)?inode\[[^\]]*,pused\]$", "inode%", "%", Util),
        m("inode_pfree", r"^vfs\.fs\.(dependent\.)?inode\[[^\]]*,pfree\]$|^vfs\.fs\.inode\.pfree\[dskPercentNode\.[0-9]+\]$", "inode 空闲%(取反)", "%", Util),
        m("io_await", r"^vfs\.dev\.(read|write)\.await\[", "磁盘 IO 延迟", "ms", Raw),

        // ---- 稳定性 ----
        m("zombies", r"^proc\.num\[[^\]]*zombie[^\]]*\]$", "僵尸进程", "", Raw),
        m("localtime", r"^system\.localtime$", "系统时间", "unixtime", Raw),
        // Agent 采集可用性
        m("agent_avail", r"^(zabbix\[host,active_agent,available\]|agent\.available|zabbix\[host\]agent\.available)$", "Agent 可用性", "", Event),
        // SNMP 采集可用性（独立字段，主流程按设备类型选用）
        m("snmp_avail", r"^zabbix\[host,snmp,available\]$", "SNMP 采集可用性", "", Event),

        // ---- 容量 ----
        m("proc_num", r"^proc\.num(\[\])?$", "进程数", "", Raw),
        m("maxfiles", r"^kernel\.maxfiles$", "fd 上限", "", Raw),
        m("openfiles", r"^kernel\.openfiles$", "打开文件数", "", Raw),
        m("tcp_service", r"^net\.tcp\.(service|port)\[", "服务探测", "", Event),

        // ---- 网络 ----
        // Agent `net.if.in["eth0"]` / `net.if.in["eth0",errors]`
        // SNMP  `net.if.in[ifHCInOctets.1]` / `net.if.in.errors[ifInErrors.1]`
        m("if_in", r"^net\.if\.in\[[^\],\]]*\]$", "网卡入流量", "B", Raw),
        m("if_in_bytes", r"^net\.if\.in\[[^\]]*,bytes\]$", "网卡入流量(bytes)", "B", Raw),
        m("if_in_err", r"^net\.if\.in\[[^\]]*,errors\]$|^net\.if\.in\.errors\[[^\]]+\]$", "网卡入错包", "", Raw),
        m("if_in_drop", r"^net\.if\.in\[[^\]]*,dropped\]$|^net\.if\.in\.discards\[[^\]]+\]$", "网卡入丢包", "", Raw),
        m("if_out", r"^net\.if\.out\[[^\],\]]*\]$", "网卡出流量", "B", Raw),
        m("if_out_bytes", r"^net\.if\.out\[[^\]]*,bytes\]$", "网卡出流量(bytes)", "B", Raw),
        m("if_out_err", r"^net\.if\.out\[[^\]]*,errors\]$|^net\.if\.out\.errors\[[^\]]+\]$", "网卡出错包", "", Raw),
        m("if_out_drop", r"^net\.if\.out\[[^\]]*,dropped\]$|^net\.if\.out\.discards\[[^\]]+\]$", "网卡出丢包", "", Raw),
        m("if_speed", r"^net\.if\.speed\[", "网卡速率", "bps", Raw),

        // ICMP（两个模板里 key 均不带参数，同时兼容带参形式）
        m("icmp_loss", r"^icmppingloss(\[.*\])?$", "ICMP 丢包率", "%", Util),
        m("icmp_sec", r"^icmppingsec(\[.*\])?$", "ICMP 延迟", "s", Raw),

        // ---- 应用与硬件（存在才启用） ----
        m("cert_days", r"cert.*(expire|valid).*days|^tls\.cert", "证书剩余天数", "d", Raw),
    ]
}

impl CompiledRules {
    /// 内置 + 用户 TOML 规则（同 id 覆盖）
    pub fn load(custom: &[MetricRule]) -> Self {
        let mut all = builtin_rules();
        for c in custom {
            if let Some(pos) = all.iter().position(|b| b.id == c.id) {
                all[pos] = c.clone();
            } else {
                all.push(c.clone());
            }
        }
        let rules = all
            .into_iter()
            .filter_map(|r| match Regex::new(&r.pattern) {
                Ok(re) => Some((re, r)),
                Err(e) => {
                    tracing::warn!("指标规则正则无效 {}：{e}", r.pattern);
                    None
                }
            })
            .collect();
        CompiledRules { rules }
    }

    pub fn match_key(&self, key: &str) -> Option<&MetricRule> {
        self.rules.iter().find(|(re, _)| re.is_match(key)).map(|(_, r)| r)
    }

    /// 按 id 查规则
    pub fn by_id(&self, id: &str) -> Option<&MetricRule> {
        self.rules.iter().find(|(_, r)| r.id == id).map(|(_, r)| r)
    }
}

impl Default for CompiledRules {
    fn default() -> Self {
        Self::load(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_match_real_keys() {
        let r = CompiledRules::default();
        for (key, expect) in [
            // ---- Agent ----
            ("system.cpu.util", "cpu_util"),
            ("vm.memory.utilization", "mem_util"),
            ("vm.memory.size[pavailable]", "mem_pavail"),
            ("system.swap.size[,pfree]", "swap_pfree"),
            ("vfs.fs.dependent.size[/data,pused]", "disk_pused"),
            ("vfs.fs.dependent.size[/boot,total]", "disk_total"),
            ("vfs.fs.dependent.inode[/,pfree]", "inode_pfree"),
            ("vfs.fs.pused[/]", "disk_pused_old"),
            ("net.if.in[\"ens3\"]", "if_in"),
            ("net.if.in[\"ens3\",errors]", "if_in_err"),
            ("net.if.in[\"ens3\",dropped]", "if_in_drop"),
            ("net.if.out[\"ens3\"]", "if_out"),
            ("net.if.speed[\"ens3\"]", "if_speed"),
            ("system.boottime", "boottime"),
            ("system.cpu.load[all,avg1]", "load1"),
            ("zabbix[host,active_agent,available]", "agent_avail"),
            ("net.tcp.port[<10.0.0.1>,9092]", "tcp_service"),
            ("proc.num", "proc_num"),
            ("kernel.maxfiles", "maxfiles"),
            ("vfs.dev.read.await[sda]", "io_await"),
            // ---- SNMP（Linux by SNMP / Windows by SNMP）----
            ("system.cpu.util[snmp,0]", "cpu_util"),
            ("system.cpu.load.avg1[laLoad.1]", "load1"),
            ("system.cpu.load.avg5[laLoad.2]", "load5"),
            ("system.cpu.load.avg15[laLoad.3]", "load15"),
            ("system.cpu.num[snmp]", "cpu_num"),
            ("vm.memory.util[snmp]", "mem_util"),
            ("vm.memory.util[memoryUsedPercentage,1]", "mem_util"),
            ("vm.memory.total[memTotalReal.0]", "mem_total"),
            ("vm.memory.total[hrStorageSize.2]", "mem_total"),
            ("system.swap.pfree[snmp]", "swap_pfree"),
            ("system.hw.uptime[hrSystemUptime.0]", "uptime"),
            ("system.net.uptime[sysUpTime.0]", "uptime"),
            ("vfs.fs.used[hrStorageUsed.1]", "disk_used"),
            ("vfs.fs.total[hrStorageSize.1]", "disk_total"),
            ("vfs.fs.inode.pfree[dskPercentNode.1]", "inode_pfree"),
            ("net.if.in[ifHCInOctets.1]", "if_in"),
            ("net.if.out[ifHCOutOctets.1]", "if_out"),
            ("net.if.in.errors[ifInErrors.1]", "if_in_err"),
            ("net.if.out.errors[ifOutErrors.1]", "if_out_err"),
            ("net.if.in.discards[ifInDiscards.1]", "if_in_drop"),
            ("net.if.out.discards[ifOutDiscards.1]", "if_out_drop"),
            ("net.if.speed[ifHighSpeed.1]", "if_speed"),
            ("icmppingloss", "icmp_loss"),
            ("icmppingsec", "icmp_sec"),
            ("zabbix[host,snmp,available]", "snmp_avail"),
        ] {
            let got = r.match_key(key).map(|m| m.id.as_str()).unwrap_or("<none>");
            assert_eq!(got, expect, "key={key}");
        }
        // 不应误匹配
        assert!(r.match_key("bigdata.flink.job.state").is_none());
        assert!(r.match_key("system.cpu.util[,idle]").is_none());
        assert!(r.match_key("agent.hostname").is_none());
    }

    #[test]
    fn extract_instances() {
        // Agent 格式：仍按原参数提取
        assert_eq!(mount_of("vfs.fs.dependent.size[/data,pused]").as_deref(), Some("/data"));
        assert_eq!(ifname_of("net.if.in[\"ens3\",errors]").as_deref(), Some("ens3"));
        assert_eq!(mount_of("vfs.fs.pused[/boot]").as_deref(), Some("/boot"));
        assert_eq!(ifname_of("net.if.in[\"ens3\"]").as_deref(), Some("ens3"));
        // SNMP 格式：同分片/同网卡的不同指标应归一化到同一名
        assert_eq!(mount_of("vfs.fs.used[hrStorageUsed.1]").as_deref(), Some("snmp1"));
        assert_eq!(mount_of("vfs.fs.total[hrStorageSize.1]").as_deref(), Some("snmp1"));
        assert_eq!(mount_of("vfs.fs.inode.pfree[dskPercentNode.1]").as_deref(), Some("snmp1"));
        assert_eq!(ifname_of("net.if.in[ifHCInOctets.1]").as_deref(), Some("if1"));
        assert_eq!(ifname_of("net.if.out[ifHCOutOctets.1]").as_deref(), Some("if1"));
        assert_eq!(ifname_of("net.if.in.errors[ifInErrors.1]").as_deref(), Some("if1"));
        assert_eq!(ifname_of("net.if.speed[ifHighSpeed.1]").as_deref(), Some("if1"));
    }
}
