//! 设备类型识别 + 兼容 Agent/SNMP 的 key 匹配工具。
//!
//! 背景：Zabbix 模板中同一指标在不同监控方式下 key 不同，例如：
//!   - Agent:        system.cpu.util
//!   - Linux SNMP:   system.cpu.util[snmp,0]
//!   - Windows SNMP: system.cpu.util（模板里本身不带参数）
//!   - 磁盘 SNMP:    vfs.fs.pused[storageUsedPercentage,1]
//! 因此需要"前缀匹配"来兼容带参数 key，并识别主机的监控方式。

use crate::types::ItemRec;

/// 主机监控方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// Zabbix Agent（Linux/Windows Agent）
    Agent,
    /// SNMP 设备（网络设备、SNMP Agent）
    Snmp,
    /// 同时挂 Agent + SNMP
    Mixed,
    /// 无法判断
    Unknown,
}

/// 监控项类型编码（Zabbix item.type）
pub mod item_type {
    pub const ZABBIX_PASSIVE: u8 = 0;   // Zabbix agent
    pub const SNMPV1: u8 = 1;           // SNMPv1 agent
    pub const TRAPPER: u8 = 2;
    pub const SIMPLE: u8 = 3;           // Simple check（icmpping 等）
    pub const SNMPV2: u8 = 4;           // SNMPv2 agent
    pub const INTERNAL: u8 = 5;
    pub const SNMPV3: u8 = 6;           // SNMPv3 agent
    pub const ZABBIX_ACTIVE: u8 = 7;
    pub const CALCULATED: u8 = 15;
    pub const DEPENDENT: u8 = 18;
}

pub fn is_agent_type(t: u8) -> bool {
    matches!(t, item_type::ZABBIX_PASSIVE | item_type::ZABBIX_ACTIVE)
}

pub fn is_snmp_type(t: u8) -> bool {
    matches!(t, item_type::SNMPV1 | item_type::SNMPV2 | item_type::SNMPV3)
}

/// 根据监控项类型判断主机类别
pub fn classify_host(items: &[ItemRec]) -> DeviceKind {
    let has_agent = items.iter().any(|i| is_agent_type(i.r#type));
    let has_snmp = items.iter().any(|i| is_snmp_type(i.r#type));
    match (has_agent, has_snmp) {
        (true, true) => DeviceKind::Mixed,
        (true, false) => DeviceKind::Agent,
        (false, true) => DeviceKind::Snmp,
        (false, false) => {
            // 兜底：只有 SIMPLE(3) 如 icmpping，也视为 SNMP 设备
            if items.iter().any(|i| i.r#type == item_type::SIMPLE) {
                DeviceKind::Snmp
            } else {
                DeviceKind::Unknown
            }
        }
    }
}

/// key 前缀匹配：`system.cpu.util[snmp,0]` 也算匹配 `system.cpu.util`
pub fn key_matches(item_key: &str, target_key: &str) -> bool {
    if item_key == target_key {
        return true;
    }
    if let Some(base) = item_key.split('[').next() {
        if base == target_key {
            return true;
        }
    }
    false
}

/// 在 item 列表里找第一个 key 匹配的项（精确或前缀）
pub fn find_item<'a>(items: &'a [ItemRec], target_key: &str) -> Option<&'a ItemRec> {
    items.iter().find(|i| key_matches(&i.key, target_key))
}

/// 在 item 列表里找所有 key 匹配的项（用于多实例指标，如多磁盘）
pub fn find_items<'a>(items: &'a [ItemRec], target_key: &str) -> Vec<&'a ItemRec> {
    items.iter().filter(|i| key_matches(&i.key, target_key)).collect()
}

/// 取第一个可解析为 f64 的 lastvalue
fn parse_first_f64<'a>(iter: impl Iterator<Item = &'a ItemRec>) -> Option<f64> {
    for it in iter {
        if let Some(v) = it.lastvalue.as_deref() {
            if let Ok(n) = v.trim().parse::<f64>() {
                if n.is_finite() {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// SNMP 采集是否失败（zabbix[host,snmp,available] == 0）
pub fn snmp_unavailable(items: &[ItemRec]) -> bool {
    find_item(items, "zabbix[host,snmp,available]")
        .and_then(|i| i.lastvalue.as_deref())
        .map(|v| v.trim() == "0")
        .unwrap_or(false)
}

/// Agent 采集是否失败（zabbix[host,agent,available] == 0）
pub fn agent_unavailable(items: &[ItemRec]) -> bool {
    find_item(items, "zabbix[host,agent,available]")
        .and_then(|i| i.lastvalue.as_deref())
        .map(|v| v.trim() == "0")
        .unwrap_or(false)
}

/// ICMP 是否不可达（icmpping == 0）
pub fn icmp_down(items: &[ItemRec]) -> bool {
    find_item(items, "icmpping")
        .and_then(|i| i.lastvalue.as_deref())
        .map(|v| v.trim() == "0")
        .unwrap_or(false)
}

/// 获取 uptime（秒）——兼容 Agent / SNMP Linux / SNMP Windows
pub fn uptime_seconds(items: &[ItemRec]) -> Option<i64> {
    for key in [
        "system.uptime",
        "system.hw.uptime[hrSystemUptime.0]",
        "system.net.uptime[sysUpTime.0]",
        "system.hw.uptime",
    ] {
        if let Some(it) = find_item(items, key) {
            if let Some(v) = it.lastvalue.as_deref() {
                if let Ok(sec) = v.trim().parse::<f64>() {
                    if sec.is_finite() {
                        return Some(sec as i64);
                    }
                }
            }
        }
    }
    None
}

/// 取百分比类指标（CPU/内存/磁盘用），兼容带参数 key。
/// candidates 按优先级给出，比如 `["system.cpu.util", "system.cpu.util[snmp]"]`。
pub fn percent_value(items: &[ItemRec], candidates: &[&str]) -> Option<f64> {
    for k in candidates {
        if let Some(n) = parse_first_f64(find_items(items, k).into_iter()) {
            return Some(n);
        }
    }
    None
}

/// 取所有磁盘使用率里的最大值（可能有多块盘，key 形如 vfs.fs.pused[...N]）
pub fn max_disk_pused(items: &[ItemRec]) -> Option<f64> {
    let mut max: Option<f64> = None;
    for it in items {
        if it.key == "vfs.fs.pused" || it.key.starts_with("vfs.fs.pused[") || it.key.starts_with("vfs.fs.pused.") {
            if let Some(v) = it.lastvalue.as_deref() {
                if let Ok(n) = v.trim().parse::<f64>() {
                    if n.is_finite() {
                        max = Some(max.map_or(n, |m| m.max(n)));
                    }
                }
            }
        }
    }
    max
}

/// 按 value_type 分类收集所有 item 的 itemid（供 history.get 分批使用）
/// value_type: 0=float, 3=unsigned, 1=char, 4=text, 2=log
pub fn itemids_by_value_type(items: &[ItemRec]) -> std::collections::HashMap<u8, Vec<String>> {
    use std::collections::HashMap;
    let mut map: HashMap<u8, Vec<String>> = HashMap::new();
    for it in items {
        // 只有数值型才有 history/trend 意义
        if matches!(it.value_type, 0 | 3) {
            map.entry(it.value_type).or_default().push(it.itemid.clone());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(key: &str, ty: u8, last: Option<&str>, vt: u8) -> ItemRec {
        ItemRec {
            itemid: format!("id-{key}"),
            hostid: "h1".into(),
            key: key.into(),
            name: key.into(),
            value_type: vt,
            units: String::new(),
            lastvalue: last.map(|s| s.to_string()),
            lastclock: None,
            status: "0".into(),
            r#type: ty,
            snmp_oid: None,
        }
    }

    #[test]
    fn test_key_prefix_match() {
        assert!(key_matches("system.cpu.util[snmp,0]", "system.cpu.util"));
        assert!(key_matches("system.cpu.util", "system.cpu.util"));
        assert!(key_matches("vfs.fs.pused[storageUsedPercentage,1]", "vfs.fs.pused"));
        assert!(!key_matches("vm.memory.util", "system.cpu.util"));
    }

    #[test]
    fn test_classify() {
        let agent = vec![mk("system.cpu.util", 0, Some("10"), 0)];
        let snmp_linux = vec![mk("system.cpu.util[snmp,0]", 4, Some("10"), 0)];
        let snmp_win = vec![mk("icmpping", 3, Some("1"), 3)];
        assert_eq!(classify_host(&agent), DeviceKind::Agent);
        assert_eq!(classify_host(&snmp_linux), DeviceKind::Snmp);
        assert_eq!(classify_host(&snmp_win), DeviceKind::Snmp);
    }

    #[test]
    fn test_percent_value_snmp() {
        let items = vec![
            mk("system.cpu.util[snmp,0]", 4, Some("42.5"), 0),
            mk("vm.memory.util[snmp]", 15, Some("88.1"), 0),
        ];
        assert_eq!(percent_value(&items, &["system.cpu.util", "system.cpu.util[snmp]"]), Some(42.5));
        assert_eq!(percent_value(&items, &["vm.memory.util", "vm.memory.util[snmp]"]), Some(88.1));
    }

    #[test]
    fn test_snmp_unavailable() {
        let items = vec![mk("zabbix[host,snmp,available]", 5, Some("0"), 3)];
        assert!(snmp_unavailable(&items));
        let items = vec![mk("zabbix[host,snmp,available]", 5, Some("1"), 3)];
        assert!(!snmp_unavailable(&items));
    }
}
