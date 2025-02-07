#[cfg(test)]
mod tests {
    use assert_cmd::prelude::*; // Add methods on commands
    use predicates::prelude::*; // Used for writing assertions
    use std::process::Command; // Run programs

    #[test]
    fn run_with_no_args() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin("apksig")?; // Run the binary

        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("Usage")); // Ensure the usage message is part of the output

        Ok(())
    }

    #[test]
    fn run_with_apk() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin("apksig")?; // Run the binary

        cmd.arg("tests/sms2call-1.0.8.apk"); // Add arguments to the command

        cmd.assert().success().stdout(predicate::str::contains(
            "tests/sms2call-1.0.8.apk length: 4952280 bytes",
        )); // Ensure the output is correct

        Ok(())
    }

    #[test]
    fn run_with_wrong_path() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin("apksig")?; // Run the binary

        cmd.arg("tests/sms2call-1.0.8.not_present"); // Add arguments to the command

        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("Error: ")); // Ensure the output is correct

        Ok(())
    }

    #[test]
    fn run_with_apk_without_signature() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin("apksig")?; // Run the binary

        cmd.arg("tests/sms2call-1.0.8_no_sig.apk"); // Add arguments to the command

        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("Error parsing APK")); // Ensure the output is correct

        Ok(())
    }
}
