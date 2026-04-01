
    #[test]
    fn test_compliance() -> Result<()> {
        let config = SdkVmConfig::from_toml(include_str!("../programs/openvm_compliance.toml"))?;
        let elf = build_example_program_at_path_with_features(
            get_programs_dir!(),
            "compliance",
            ["k256"],
            &NoInitFile,
        )?;
        let openvm_exe = VmExe::from_elf(elf, config.transpiler())?;

        let witness_bytes = build_default_witness();
        let mut stdin = StdIn::default();
        stdin.write_bytes(&witness_bytes);

        println!("Proving compliance circuit...");
        let start = std::time::Instant::now();
        air_test_with_min_segments(SdkVmBuilder, config, openvm_exe, stdin, 1);
        println!("Proof time: {:?}", start.elapsed());
        Ok(())
    }

    fn build_default_witness() -> Vec<u8> {
        use sha2::{Sha256 as StdSha256, digest::Digest as StdDigest};
        let hash = |data: &[u8]| -> [u8; 32] { StdSha256::digest(data).into() };
        let nf_key = [0u8; 32];
        let nk_cm = hash(&nf_key);
        let mut consumed = Vec::new();
        consumed.extend_from_slice(&[0u8; 32]); consumed.extend_from_slice(&[0u8; 32]);
        consumed.extend_from_slice(&1u128.to_be_bytes()); consumed.extend_from_slice(&[0u8; 32]);
        consumed.push(0); consumed.extend_from_slice(&[0u8; 32]);
        consumed.extend_from_slice(&nk_cm); consumed.extend_from_slice(&[0u8; 32]);
        let mut psi_in = b"RISC0_ExpandSeed".to_vec(); psi_in.push(0); psi_in.extend_from_slice(&[0u8;64]);
        let psi = hash(&psi_in);
        let mut rcm_in = b"RISC0_ExpandSeed".to_vec(); rcm_in.push(1); rcm_in.extend_from_slice(&[0u8;64]);
        let rcm = hash(&rcm_in);
        let mut cm_in = Vec::new();
        cm_in.extend_from_slice(&[0u8;32]); cm_in.extend_from_slice(&[0u8;32]);
        cm_in.extend_from_slice(&1u128.to_be_bytes()); cm_in.extend_from_slice(&[0u8;32]);
        cm_in.push(0); cm_in.extend_from_slice(&[0u8;32]);
        cm_in.extend_from_slice(&nk_cm); cm_in.extend_from_slice(&rcm);
        let cm = hash(&cm_in);
        let mut nf_in = Vec::new();
        nf_in.extend_from_slice(&nf_key); nf_in.extend_from_slice(&[0u8;32]);
        nf_in.extend_from_slice(&psi); nf_in.extend_from_slice(&cm);
        let nf = hash(&nf_in);
        let mut created = Vec::new();
        created.extend_from_slice(&[0u8;32]); created.extend_from_slice(&[0u8;32]);
        created.extend_from_slice(&1u128.to_be_bytes()); created.extend_from_slice(&[0u8;32]);
        created.push(0); created.extend_from_slice(&nf);
        created.extend_from_slice(&nk_cm); created.extend_from_slice(&[0u8;32]);
        let mut w = Vec::new();
        w.extend_from_slice(&consumed); w.extend_from_slice(&created);
        w.extend_from_slice(&hex::decode("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06").unwrap());
        w.extend_from_slice(&nf_key);
        w.push(10);
        for _ in 0..10 { w.extend_from_slice(&[0u8;32]); w.push(0); }
        let mut rcv = [0u8; 32]; rcv[0] = 1; w.extend_from_slice(&rcv);
        w
    }
