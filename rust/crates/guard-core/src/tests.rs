use super::*;

    #[test]
    fn cpu_guard_sustained_trigger_hysteresis_hold_and_recovery_reset() {
        let mut cfg = CpuGuardConfig::default();
        cfg.interval_seconds = 300.0;
        cfg.explicit_required_duration_override = true;
        let mut tracker = CpuGuardTracker::new(cfg);

        let host_high = HostCpuSample {
            ready: true,
            busy_percent: 90.0,
            logical_cpus: 4,
            load_1m: Some(5.0),
            psi_some_avg10: Some(12.0),
        };
        let host_warming = HostCpuSample {
            ready: false,
            busy_percent: 0.0,
            logical_cpus: 4,
            load_1m: None,
            psi_some_avg10: None,
        };
        let c_high = vec![CpuContainerSample {
            key: "podman|default|c1".into(),
            cpu_percent: Some(360.0),
            effective_cpus: 4.0,
            cgroup_cpu_psi_some_avg10: Some(10.0),
        }];

        // Sample 1 & 2 -> Watching
        let out1 = tracker.observe(1000, &host_high, &c_high, true);
        assert_eq!(out1.decisions[0].stage, GuardStage::Watching);
        assert_eq!(out1.decisions[0].high_samples, 1);
        assert!(out1.actions.is_empty());

        let out2 = tracker.observe(1300, &host_high, &c_high, true);
        assert_eq!(out2.decisions[0].stage, GuardStage::Watching);
        assert_eq!(out2.decisions[0].high_samples, 2);

        // Transient warming sample within max_gap (750s) -> hysteresis hold preserves candidate
        let out_warm = tracker.observe(1500, &host_warming, &c_high, true);
        assert_eq!(out_warm.decisions[0].stage, GuardStage::SamplingUnavailable);
        assert!(out_warm.actions.is_empty());

        // Sample 3 at t=1600 (600s elapsed, 3 samples) -> triggers Tier 1 (50% of 4.0 = 2.0 CPUs)
        let out3 = tracker.observe(1600, &host_high, &c_high, true);
        assert_eq!(out3.decisions[0].stage, GuardStage::Active);
        assert_eq!(out3.decisions[0].tier, 1);
        assert_eq!(
            out3.actions,
            vec![CpuGuardAction::ApplyLimit {
                key: "podman|default|c1".into(),
                tier: 1,
                target_cpus: 2.0,
                fair_share_cpus: None,
                pressure_basis: "host_busy_and_psi_confirmed",
            }]
        );

        // Recovery begins: ratio = 40 / (2.0 * 100) = 0.2 <= 0.5, host busy 30 < 70, psi 0.5 < 2
        let host_low = HostCpuSample {
            ready: true,
            busy_percent: 30.0,
            logical_cpus: 4,
            load_1m: Some(0.5),
            psi_some_avg10: Some(0.5),
        };
        let c_low = vec![CpuContainerSample {
            key: "podman|default|c1".into(),
            cpu_percent: Some(40.0),
            effective_cpus: 4.0,
            cgroup_cpu_psi_some_avg10: Some(0.1),
        }];
        let r1 = tracker.observe(1900, &host_low, &c_low, true);
        assert_eq!(r1.decisions[0].stage, GuardStage::Active);
        assert_eq!(r1.decisions[0].low_samples, 1);

        // Spike resets recovery counter!
        let r_spike = tracker.observe(2200, &host_high, &c_high, true);
        assert_eq!(r_spike.decisions[0].low_samples, 0);

        // 3 consecutive low samples over 600s -> Restore + Cooldown
        assert_eq!(tracker.observe(2500, &host_low, &c_low, true).decisions[0].low_samples, 1);
        assert_eq!(tracker.observe(2800, &host_low, &c_low, true).decisions[0].low_samples, 2);
        let r_done = tracker.observe(3100, &host_low, &c_low, true);
        assert_eq!(r_done.decisions[0].stage, GuardStage::Restored);
        assert_eq!(
            r_done.actions,
            vec![CpuGuardAction::RestoreLimit {
                key: "podman|default|c1".into(),
                original_cpus: 4.0,
                cooldown_until: 4000,
            }]
        );

        // In cooldown before t=4000
        let cd = tracker.observe(3500, &host_high, &c_high, true);
        assert_eq!(cd.decisions[0].stage, GuardStage::Cooldown);
        assert_eq!(cd.decisions[0].cooldown_remaining_seconds, 500);
    }

    #[test]
    fn cpu_guard_multi_container_contention_fair_share_target() {
        let mut tracker = CpuGuardTracker::new(CpuGuardConfig::default());
        let host = HostCpuSample {
            ready: true,
            busy_percent: 92.0,
            logical_cpus: 2,
            load_1m: Some(4.0),
            psi_some_avg10: Some(15.0),
        };
        let containers = vec![
            CpuContainerSample {
                key: "c1".into(),
                cpu_percent: Some(90.0),
                effective_cpus: 2.0,
                cgroup_cpu_psi_some_avg10: Some(8.0),
            },
            CpuContainerSample {
                key: "c2".into(),
                cpu_percent: Some(80.0),
                effective_cpus: 2.0,
                cgroup_cpu_psi_some_avg10: Some(8.0),
            },
        ];

        // Runaway / contention window: 180s, 2 samples at interval 300s
        let out1 = tracker.observe(1000, &host, &containers, true);
        assert!(out1.multi_container_contention);
        assert_eq!(out1.decisions[0].stage, GuardStage::Watching);
        assert_eq!(out1.decisions[1].stage, GuardStage::Watching);

        let out2 = tracker.observe(1300, &host, &containers, true);
        assert_eq!(out2.actions.len(), 2);
        // Fair share for 2 contending containers on 2 CPUs: (0.85 * 2) / 2 = 0.85 CPUs
        // Baseline 2.0 * 0.5 = 1.0, capped by fair_share 0.85 -> 0.85 CPUs
        for action in &out2.actions {
            match action {
                CpuGuardAction::ApplyLimit {
                    target_cpus,
                    fair_share_cpus,
                    ..
                } => {
                    assert!((*fair_share_cpus).unwrap() - 0.85 < 1e-9);
                    assert!((*target_cpus - 0.85).abs() < 1e-9);
                }
                other => panic!("unexpected action: {:?}", other),
            }
        }
    }

    #[test]
    fn memory_guard_psi_avg10_avg60_trigger_escalation_and_recovery() {
        let mut tracker = MemoryGuardTracker::new(MemoryGuardConfig::default());
        let max_bytes = 1024 * 1024 * 1024; // 1 GiB
        let c_high = vec![MemoryContainerSample {
            key: "incus|default|m1".into(),
            current_bytes: 900 * 1024 * 1024, // ~87.9% >= 85%
            max_bytes: Some(max_bytes),
            original_high_bytes: None,
            container_psi: PsiSample::new(None, Some(8.0)), // avg60 fallback
        }];
        let host_high = PsiSample::new(Some(7.5), Some(6.0));

        // 3 samples over 600s -> Tier 1 (90% of 1 GiB)
        assert_eq!(tracker.observe(1000, host_high, &c_high, true).0[0].stage, GuardStage::Watching);
        assert_eq!(tracker.observe(1300, host_high, &c_high, true).0[0].stage, GuardStage::Watching);
        let (decs, acts) = tracker.observe(1600, host_high, &c_high, true);
        assert_eq!(decs[0].stage, GuardStage::Active);
        assert_eq!(decs[0].tier, 1);
        assert_eq!(
            acts,
            vec![MemoryGuardAction::ApplyMemoryHigh {
                key: "incus|default|m1".into(),
                tier: 1,
                target_bytes: memory_tier_target_bytes(max_bytes, 1),
            }]
        );

        // Escalation window: 3 samples over 600s -> Tier 2 (80% of 1 GiB)
        tracker.observe(1900, host_high, &c_high, true);
        tracker.observe(2200, host_high, &c_high, true);
        let (decs_esc, acts_esc) = tracker.observe(2500, host_high, &c_high, true);
        assert_eq!(decs_esc[0].tier, 2);
        assert_eq!(
            acts_esc,
            vec![MemoryGuardAction::EscalateMemoryHigh {
                key: "incus|default|m1".into(),
                tier: 2,
                target_bytes: memory_tier_target_bytes(max_bytes, 2),
            }]
        );

        // Recovery: 4 samples over 900s with PSI < 2.0 and usage < 95%
        let host_low = PsiSample::new(Some(0.5), Some(0.8));
        let c_low = vec![MemoryContainerSample {
            key: "incus|default|m1".into(),
            current_bytes: 500 * 1024 * 1024,
            max_bytes: Some(max_bytes),
            original_high_bytes: None,
            container_psi: PsiSample::new(Some(0.4), Some(0.5)),
        }];
        assert_eq!(tracker.observe(2800, host_low, &c_low, true).0[0].low_samples, 1);
        // Pressure spike resets recovery counter
        assert_eq!(tracker.observe(3100, host_high, &c_high, true).0[0].low_samples, 0);

        assert_eq!(tracker.observe(3400, host_low, &c_low, true).0[0].low_samples, 1);
        assert_eq!(tracker.observe(3700, host_low, &c_low, true).0[0].low_samples, 2);
        assert_eq!(tracker.observe(4000, host_low, &c_low, true).0[0].low_samples, 3);
        let (decs_rec, acts_rec) = tracker.observe(4300, host_low, &c_low, true);
        assert_eq!(decs_rec[0].stage, GuardStage::Restored);
        assert_eq!(
            acts_rec,
            vec![MemoryGuardAction::RestoreMemoryHigh {
                key: "incus|default|m1".into(),
                original_high_bytes: None,
                cooldown_until: 5200,
            }]
        );
    }

    #[test]
    fn io_guard_diskstats_psi_fallback_trigger_and_recovery() {
        let mut tracker = IoGuardTracker::new(IoGuardConfig::default());
        let host_devs = vec![HostDeviceSample {
            device: "8:0".into(),
            busy_percent: 90.0,
            total_bps: 100.0 * 1024.0 * 1024.0,
            total_iops: 1000.0,
        }];
        let c_high = vec![IoContainerSample {
            key: "runman|default|r1".into(),
            device_rates: vec![(
                "8:0".into(),
                IoRates {
                    rbps: 80.0 * 1024.0 * 1024.0,
                    wbps: 0.0, // below 1 MiB/s floor -> stays None ("max")
                    riops: 800.0,
                    wiops: 0.0, // below 25 IOPS floor -> stays None ("max")
                },
            )],
            original_limits: HashMap::new(),
        }];

        // Host PSI unavailable -> falls back to diskstats busy >= 80%
        let (d1, a1) = tracker.observe(1000, true, &host_devs, None, &c_high, true);
        assert_eq!(d1[0].stage, GuardStage::Watching);
        assert_eq!(d1[0].pressure_basis, "device_busy_fallback_psi_unavailable");
        assert!(a1.is_empty());

        let (d2, a2) = tracker.observe(1300, true, &host_devs, None, &c_high, true);
        assert_eq!(d2[0].stage, GuardStage::Active);
        assert_eq!(d2[0].tier, 1);
        assert_eq!(
            a2,
            vec![IoGuardAction::ApplyIoMax {
                key: "runman|default|r1".into(),
                device: "8:0".into(),
                tier: 1,
                target: IoMaxLimits {
                    rbps: Some(40 * 1024 * 1024),
                    wbps: None,
                    riops: Some(400),
                    wiops: None,
                },
            }]
        );

        // Recovery: busy 40% < 60% and observed <= 50% of applied, 3 samples over 600s
        let host_low = vec![HostDeviceSample {
            device: "8:0".into(),
            busy_percent: 40.0,
            total_bps: 10.0 * 1024.0 * 1024.0,
            total_iops: 100.0,
        }];
        let c_low = vec![IoContainerSample {
            key: "runman|default|r1".into(),
            device_rates: vec![(
                "8:0".into(),
                IoRates {
                    rbps: 5.0 * 1024.0 * 1024.0,
                    wbps: 0.0,
                    riops: 50.0,
                    wiops: 0.0,
                },
            )],
            original_limits: HashMap::new(),
        }];
        assert_eq!(tracker.observe(1600, true, &host_low, None, &c_low, true).0[0].low_samples, 1);
        assert_eq!(tracker.observe(1900, true, &host_low, None, &c_low, true).0[0].low_samples, 2);
        let (d_rec, a_rec) = tracker.observe(2200, true, &host_low, None, &c_low, true);
        assert_eq!(d_rec[0].stage, GuardStage::Restored);
        assert_eq!(
            a_rec,
            vec![IoGuardAction::RestoreIoMax {
                key: "runman|default|r1".into(),
                device: "8:0".into(),
                original: IoMaxLimits::default(),
                cooldown_until: 3100,
            }]
        );
    }

    #[test]
    fn cpu_guard_single_core_saturated_host_triggers_above_70_without_reset() {
        let mut cfg = CpuGuardConfig::default();
        cfg.interval_seconds = 60.0;
        let mut tracker = CpuGuardTracker::new(cfg);

        let host_saturated = HostCpuSample {
            ready: true,
            busy_percent: 100.0,
            logical_cpus: 1,
            load_1m: Some(2.44),
            psi_some_avg10: Some(0.5),
        };
        let c_73 = vec![CpuContainerSample {
            key: "runman|default|4a4c84c1".into(),
            cpu_percent: Some(73.0),
            effective_cpus: 1.0,
            cgroup_cpu_psi_some_avg10: Some(0.2),
        }];
        let c_88 = vec![CpuContainerSample {
            key: "runman|default|4a4c84c1".into(),
            cpu_percent: Some(88.0),
            effective_cpus: 1.0,
            cgroup_cpu_psi_some_avg10: Some(0.2),
        }];

        let o1 = tracker.observe(1000, &host_saturated, &c_73, true);
        assert_eq!(o1.decisions[0].stage, GuardStage::Watching);
        assert_eq!(o1.decisions[0].high_samples, 1);
        assert_eq!(o1.decisions[0].pressure_basis, "single_core_host_cpu_saturation");

        let o2 = tracker.observe(1060, &host_saturated, &c_88, true);
        assert_eq!(o2.decisions[0].high_samples, 2);

        let o3 = tracker.observe(1120, &host_saturated, &c_73, true);
        assert_eq!(o3.decisions[0].high_samples, 3);

        let o4 = tracker.observe(1180, &host_saturated, &c_88, true);
        assert_eq!(o4.decisions[0].stage, GuardStage::Active);
        assert_eq!(
            o4.actions,
            vec![CpuGuardAction::ApplyLimit {
                key: "runman|default|4a4c84c1".into(),
                tier: 1,
                target_cpus: 0.5,
                fair_share_cpus: None,
                pressure_basis: "single_core_host_cpu_saturation",
            }]
        );
    }
