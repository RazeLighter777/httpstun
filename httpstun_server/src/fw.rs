
pub fn create_masquerade_rule(tun_if_name: &str, external_if_name: &str) -> Result<(), String> {
    let output = std::process::Command::new("iptables")
        .args(&[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            external_if_name,
            "-j",
            "MASQUERADE",
            "-m",
            "comment",
            "--comment",
            &format!("httpstun_masquerade_{}", tun_if_name),
        ])
        .output()
        .map_err(|e| format!("Failed to execute iptables command: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to add masquerade rule: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub fn remove_masquerade_rule(tun_if_name: &str, external_if_name: &str) -> Result<(), String> {
    let output = std::process::Command::new("iptables")
        .args(&[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            external_if_name,
            "-j",
            "MASQUERADE",
            "-m",
            "comment",
            "--comment",
            &format!("httpstun_masquerade_{}", tun_if_name),
        ])
        .output()
        .map_err(|e| format!("Failed to execute iptables command: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to remove masquerade rule: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub fn remove_existing_masquerade_rules_with_comment(tun_if_name: &str) -> Result<(), String> {
    let comment = format!("httpstun_masquerade_{}", tun_if_name);
    loop {
        let output = std::process::Command::new("iptables")
            .args(&[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "MASQUERADE",
            ])
            .output()
            .map_err(|e| format!("Failed to execute iptables command: {}", e))?;
        if !output.status.success() {
            // If the rule was not found, we can break the loop
            if output.status.code() == Some(1) {
                break;
            } else {
                return Err(format!(
                    "Failed to remove existing masquerade rule: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
    }
    Ok(())
}