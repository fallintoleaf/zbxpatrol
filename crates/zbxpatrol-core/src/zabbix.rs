    pub async fn get_items(&self, hostid: &str) -> Result<Vec<ItemRec>> {
        let params = json!({
            "hostids": [hostid],
            "output": [
                "itemid","key_","name","value_type","units",
                "lastvalue","lastclock","state","status",
                "type",        // 👈 新增：监控项类型
                "snmp_oid"     // 👈 新增：SNMP OID（非 SNMP 项为空字符串）
            ],
            "monitored": true,
            "sortfield": "key_",
            "limit": 5000,
        });
        let v = self.call("item.get", params).await?;
        Ok(parse_array(&v, |it| ItemRec {
            itemid: it["itemid"].as_str().unwrap_or_default().into(),
            hostid: hostid.into(),
            key: it["key_"].as_str().unwrap_or_default().into(),
            name: it["name"].as_str().unwrap_or_default().into(),
            value_type: it["value_type"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
            units: it["units"].as_str().unwrap_or_default().into(),
            lastvalue: it["lastvalue"].as_str().map(|s| s.to_string()),
            lastclock: it["lastclock"].as_str().and_then(|s| s.parse().ok()),
            status: it["status"].as_str().unwrap_or_default().into(),
            r#type: it["type"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
            snmp_oid: it["snmp_oid"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        }))
    }
