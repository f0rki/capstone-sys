//! # libcapstone.so.3 bindings
//!
//! If you want to compile this for another target,  `wasm32-unknown-emscripten`, for example,
//! it is currently recommended to pass the feature flag `use_bundled_capstone_cmake` to
//! build capstone using the cmake build system (which requires cmake to be installed).
//!
//! This has seen some (limited) testing and has been seen to work on the
//! `wasm32-unknown-emscripten` target at least.
//!
//! Compiling on windows has not been tested, although this should be easy to setup.
//!
//! The following architectures are supported:
//!
//! * `arm`: ARM
//! * `arm64`: ARM64 (also known as AArch64)
//! * `mips`: MIPS
//! * `ppc`: PowerPC
//! * `sparc`: SPARC
//! * `sysz`: System z
//! * `x86`: x86 family (includes 16, 32, and 64 bit modes)
//! * `xcore`: XCore
//! * `evm`: EVM
//!
//! For each architecture, *at least* the following types are defined (replace `ARCH` with
//! architecture names shown above):
//!
//! * `enum ARCH_insn`: instruction ids
//! * `enum ARCH_insn_group`: architecture-specific group ids
//! * `enum ARCH_op_type`: instruction operand types ids
//! * `enum ARCH_reg`<sup>1</sup>: register ids
//! * `struct ARCH_op_mem`: operand referring to memory
//! * `struct cs_ARCH_op`: instruction operand
//! * `struct cs_ARCH`: instruction
//!
//! **Note**: documentation for functions/types was taken directly from
//! [Capstone C headers][capstone headers].
//!
//! [capstone headers]: https://github.com/capstone-rust/capstone-sys/blob/master/capstone/include/capstone.h
//! <sup>1</sup>: Defined as a ["constified" enum modules](https://docs.rs/bindgen/0.30.0/bindgen/struct.Builder.html#method.constified_enum_module)
//!               because discriminant values are not unique. Rust requires discriminant values to be unique.

// Suppress errors from Capstone names
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::os::raw::c_int;

// Bindings should be copied here
include!(concat!(env!("OUT_DIR"), "/capstone.rs"));

pub const CS_SUPPORT_DIET: c_int = (cs_arch::CS_ARCH_ALL as c_int) + 1;
pub const CS_SUPPORT_X86_REDUCE: c_int = (cs_arch::CS_ARCH_ALL as c_int) + 2;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/common.rs"));

#[cfg(test)]
/// Many of the tests contain statements without effect; these "tests" are just to ensure that
/// types have been defined by bindgen.
mod test {
    #![allow(unused_imports)]
    #![allow(path_statements)]
    use super::*;
    use std::ffi::CStr;
    use std::iter::Zip;
    use std::os::raw::{c_char, c_int, c_uint, c_void};
    use std::slice;

    #[test]
    fn test_arch_arm() {
        // Common constants
        arm_insn::ARM_INS_ADC;
        arm_insn_group::ARM_GRP_JUMP;
        arm_op_type::ARM_OP_REG;
        arm_reg::ARM_REG_PC;

        // Common structs
        arm_op_mem {
            base: 0,
            index: 0,
            scale: 0,
            disp: 0,
            lshift: 0,
        };

        // Union types
        let shift = cs_arm_op__bindgen_ty_1 {
            type_: arm_shifter::ARM_SFT_ASR,
            value: 0,
        };
        let op = cs_arm_op {
            vector_index: 0,
            shift: shift,
            type_: arm_op_type::ARM_OP_REG,
            __bindgen_anon_1: cs_arm_op__bindgen_ty_2 { reg: 0 },
            subtracted: false,
            access: 0,
            neon_lane: -1,
        };
        cs_arm {
            usermode: false,
            vector_size: 0,
            vector_data: arm_vectordata_type::ARM_VECTORDATA_I8,
            cps_mode: arm_cpsmode_type::ARM_CPSMODE_IE,
            cps_flag: arm_cpsflag_type::ARM_CPSFLAG_F,
            cc: arm_cc::ARM_CC_EQ,
            update_flags: false,
            writeback: false,
            mem_barrier: arm_mem_barrier::ARM_MB_OSHLD,
            op_count: 0,
            operands: [op; 36],
        };

        // ARM-specific constants
        arm_cc::ARM_CC_EQ;
        arm_cpsflag_type::ARM_CPSFLAG_F;
        arm_cpsmode_type::ARM_CPSMODE_IE;
        arm_mem_barrier::ARM_MB_OSHLD;
        arm_setend_type::ARM_SETEND_BE;
        arm_shifter::ARM_SFT_ASR;
        arm_sysreg::ARM_SYSREG_SPSR_C;
        arm_vectordata_type::ARM_VECTORDATA_I8;
    }

    #[test]
    fn test_arch_arm64() {
        // Common constants
        arm64_insn::ARM64_INS_ADC;
        arm64_insn_group::ARM64_GRP_JUMP;
        arm64_op_type::ARM64_OP_REG;
        arm64_reg::ARM64_REG_B0;

        // Common structs
        arm64_op_mem {
            base: 0,
            index: 0,
            disp: 0,
        };

        // Union types
        let shift = cs_arm64_op__bindgen_ty_1 {
            type_: arm64_shifter::ARM64_SFT_LSL,
            value: 0,
        };
        let op = cs_arm64_op {
            vector_index: 0,
            vas: arm64_vas::ARM64_VAS_8B,
            vess: arm64_vess::ARM64_VESS_B,
            shift: shift,
            ext: arm64_extender::ARM64_EXT_UXTB,
            type_: arm64_op_type::ARM64_OP_REG,
            __bindgen_anon_1: cs_arm64_op__bindgen_ty_2 { reg: 0 },
            access: 0,
        };
        cs_arm64 {
            cc: arm64_cc::ARM64_CC_EQ,
            update_flags: false,
            writeback: false,
            op_count: 0,
            operands: [op; 8],
        };

        // ARM64-specific constants
        arm64_at_op::ARM64_AT_S1E1R;
        arm64_barrier_op::ARM64_BARRIER_OSHLD;
        arm64_cc::ARM64_CC_EQ;
        arm64_dc_op::ARM64_DC_ZVA;
        arm64_extender::ARM64_EXT_UXTB;
        arm64_ic_op::ARM64_IC_IALLUIS;

        // arm64_mrs_reg was renamed to arm64_sysreg
        arm64_sysreg::ARM64_SYSREG_MDCCSR_EL0;

        arm64_msr_reg::ARM64_SYSREG_DBGDTRTX_EL0;
        arm64_prefetch_op::ARM64_PRFM_PLDL1KEEP;
        arm64_pstate::ARM64_PSTATE_SPSEL;
        arm64_shifter::ARM64_SFT_LSL;
        arm64_tlbi_op::ARM64_TLBI_VMALLE1IS;
        arm64_vas::ARM64_VAS_8B;
        arm64_vess::ARM64_VESS_B;
    }

    #[test]
    fn test_arch_mips() {
        // Common constants
        mips_insn::MIPS_INS_ADD;
        mips_insn_group::MIPS_GRP_JUMP;
        mips_op_type::MIPS_OP_REG;
        mips_reg::MIPS_REG_0;

        // Common structs
        mips_op_mem { base: 0, disp: 0 };

        // Union structs
        let op = cs_mips_op {
            type_: mips_op_type::MIPS_OP_REG,
            __bindgen_anon_1: cs_mips_op__bindgen_ty_1 { reg: 0 },
        };
        cs_mips {
            op_count: 0,
            operands: [op; 10],
        };

        // There are no MIPS-specific types
    }

    #[test]
    fn test_arch_ppc() {
        // Common constants
        ppc_insn::PPC_INS_ADD;
        ppc_insn_group::PPC_GRP_JUMP;
        ppc_op_type::PPC_OP_REG;
        ppc_reg::PPC_REG_R0;

        // Common structs
        ppc_op_mem {
            base: ppc_reg::PPC_REG_R0,
            disp: 0,
        };

        // Union structs
        let op = cs_ppc_op {
            type_: ppc_op_type::PPC_OP_REG,
            __bindgen_anon_1: cs_ppc_op__bindgen_ty_1 {
                reg: ppc_reg::PPC_REG_CARRY,
            },
        };
        cs_ppc {
            bc: ppc_bc::PPC_BC_LT,
            bh: ppc_bh::PPC_BH_PLUS,
            update_cr0: false,
            op_count: 0,
            operands: [op; 8],
        };

        // PowerPC-specific constants
        ppc_bc::PPC_BC_LT;
        ppc_bh::PPC_BH_PLUS;

        // PowerPC-specific structs
        ppc_op_crx {
            scale: 0,
            reg: ppc_reg::PPC_REG_R0,
            cond: ppc_bc::PPC_BC_LT,
        };
    }

    #[test]
    fn test_arch_sparc() {
        // Common constants
        sparc_insn::SPARC_INS_ADDCC;
        sparc_insn_group::SPARC_GRP_JUMP;
        sparc_op_type::SPARC_OP_REG;
        sparc_reg::SPARC_REG_SP;

        // Common structs
        sparc_op_mem {
            base: 0,
            index: 0,
            disp: 0,
        };

        // Union structs
        let op = cs_sparc_op {
            type_: sparc_op_type::SPARC_OP_REG,
            __bindgen_anon_1: cs_sparc_op__bindgen_ty_1 { reg: 0 },
        };
        cs_sparc {
            cc: sparc_cc::SPARC_CC_ICC_A,
            hint: sparc_hint::SPARC_HINT_A,
            op_count: 0,
            operands: [op; 4],
        };

        // SPARC-specific constants
        sparc_cc::SPARC_CC_ICC_A;
        sparc_hint::SPARC_HINT_A;
    }

    #[test]
    fn test_arch_sysz() {
        // Common constants
        sysz_insn::SYSZ_INS_A;
        sysz_insn_group::SYSZ_GRP_JUMP;
        sysz_op_type::SYSZ_OP_REG;
        sysz_reg::SYSZ_REG_0;

        // Common structs
        sysz_op_mem {
            base: 0,
            index: 0,
            length: 0,
            disp: 0,
        };
        let op = cs_sysz_op {
            type_: sysz_op_type::SYSZ_OP_REG,
            __bindgen_anon_1: cs_sysz_op__bindgen_ty_1 { reg: 0 },
        };
        cs_sysz {
            cc: sysz_cc::SYSZ_CC_O,
            op_count: 0,
            operands: [op; 6],
        };

        // System z-specific constants
        sysz_cc::SYSZ_CC_O;
    }

    #[test]
    fn test_arch_x86() {
        // Common constants
        x86_insn::X86_INS_AAA;
        x86_insn_group::X86_GRP_JUMP;
        x86_op_type::X86_OP_REG;
        x86_reg::X86_REG_AH;

        // Common structs
        x86_op_mem {
            segment: 0,
            base: 0,
            index: 0,
            scale: 0,
            disp: 0,
        };

        // Union types
        let op = cs_x86_op {
            type_: x86_op_type::X86_OP_REG,
            __bindgen_anon_1: cs_x86_op__bindgen_ty_1 {
                reg: x86_reg::X86_REG_AH,
            },
            size: 0,
            avx_bcast: x86_avx_bcast::X86_AVX_BCAST_2,
            avx_zero_opmask: false,
            access: 0,
        };
        cs_x86 {
            prefix: [0; 4],
            opcode: [0; 4],
            rex: 0,
            addr_size: 0,
            modrm: 0,
            sib: 0,
            disp: 0,
            sib_index: x86_reg::X86_REG_AH,
            sib_scale: 0,
            sib_base: x86_reg::X86_REG_AH,
            sse_cc: x86_sse_cc::X86_SSE_CC_EQ,
            avx_cc: x86_avx_cc::X86_AVX_CC_EQ,
            avx_sae: false,
            avx_rm: x86_avx_rm::X86_AVX_RM_RN,
            op_count: 0,
            operands: [op; 8],
            encoding: cs_x86_encoding {
                modrm_offset: 0,
                disp_offset: 0,
                disp_size: 0,
                imm_offset: 0,
                imm_size: 0,
            },
            xop_cc: x86_xop_cc::X86_XOP_CC_INVALID,
            __bindgen_anon_1: cs_x86__bindgen_ty_1 { eflags: 0 },
        };

        // x86-specific constants
        x86_avx_bcast::X86_AVX_BCAST_2;
        x86_avx_cc::X86_AVX_CC_EQ;
        x86_avx_rm::X86_AVX_RM_RN;
        x86_prefix::X86_PREFIX_LOCK;
        x86_sse_cc::X86_SSE_CC_EQ;
    }

    #[test]
    fn test_arch_xcore() {
        // Common constants
        xcore_insn::XCORE_INS_ADD;
        xcore_insn_group::XCORE_GRP_JUMP;
        xcore_op_type::XCORE_OP_REG;
        xcore_reg::XCORE_REG_CP;

        // Common structs
        xcore_op_mem {
            base: 0,
            index: 0,
            disp: 0,
            direct: 0,
        };

        // Union types
        let op = cs_xcore_op {
            type_: xcore_op_type::XCORE_OP_REG,
            __bindgen_anon_1: cs_xcore_op__bindgen_ty_1 { reg: 0 },
        };
        cs_xcore {
            op_count: 0,
            operands: [op; 8],
        };

        // There are no XCore-specific types
    }

    #[test]
    fn test_non_arch_types() {
        // Structs
        cs_opt_mem {
            malloc: None,
            calloc: None,
            realloc: None,
            free: None,
            vsnprintf: None,
        };
        cs_opt_skipdata {
            mnemonic: 0 as *const c_char,
            callback: None,
            user_data: 0 as *mut c_void,
        };
        /*
        cs_detail {
            regs_read: [0; 12],
            regs_read_count: 0,
            regs_read: [0; 12],
            regs_read_count: 0,
            regs_read: [0; 12],
            regs_read_count: 0,
            __bindgen_anon_1: 0,
        };
        */
        cs_insn {
            id: 0,
            address: 0,
            size: 0,
            bytes: [0; 33],
            mnemonic: [0; 32],
            op_str: [0; 160],
            detail: 0 as *mut cs_detail,
        };

        // Constants
        cs_arch::CS_ARCH_ARM;
        CS_MODE_LITTLE_ENDIAN;
        cs_opt_type::CS_OPT_SYNTAX;
        cs_opt_value::CS_OPT_OFF;
        cs_op_type::CS_OP_REG;
        cs_group_type::CS_GRP_JUMP;
        cs_err::CS_ERR_OK;
    }

    #[test]
    fn test_cs_version() {
        let mut major: c_int = 0;
        let mut minor: c_int = 0;
        let major_ptr: *mut c_int = &mut major;
        let minor_ptr: *mut c_int = &mut minor;

        let _ = unsafe { cs_version(major_ptr, minor_ptr) };

        println!("Capstone version (major, minor) = {:?}", (major, minor));

        assert!(major == 4, "Invalid major version {:?}", major);
        assert!(
            minor >= 0 && minor < 1000,
            "Invalid minor version {:?}",
            minor
        );
    }

    #[test]
    fn test_cs_support() {
        assert!(unsafe { cs_support(cs_arch::CS_ARCH_ARM as c_int) });
        assert!(unsafe { cs_support(cs_arch::CS_ARCH_X86 as c_int) });
        assert!(!unsafe { cs_support(CS_SUPPORT_DIET as c_int) });
    }

    /// Convert a NUL delimited C string to a Rust string
    fn convert_char_array_to_string(str_buf: &[c_char]) -> String {
        let cow = unsafe { CStr::from_ptr(str_buf.as_ptr()).to_string_lossy() };
        String::from(cow)
    }

    /// Verify capstone disassembles instructions correctly
    fn test_disassembly_helper(arch: cs_arch, mode: cs_mode, code: &[(&[u8], &str, u32)]) {
        // Create handle
        let mut handle: csh = 0;
        let result = unsafe { cs_open(arch, mode, &mut handle as *mut csh) };
        assert!(result == cs_err::CS_ERR_OK);

        // Concatenate instruction bytes into a single buffer
        let mut code_bytes: Vec<u8> = Vec::new();
        for &(bytes, _, _) in code.iter() {
            code_bytes.extend_from_slice(bytes);
        }

        // Disassemble buffer
        let mut insn_ptr: *mut cs_insn = 0 as *mut cs_insn;
        let mut address = 0x1000;
        let count = unsafe {
            cs_disasm(
                handle,
                code_bytes.as_ptr(),
                code_bytes.len(),
                address,
                0,
                &mut insn_ptr as *mut *mut cs_insn,
            )
        };

        assert!(count == code.len());

        // Verify instructions match
        let insns: &[cs_insn] = unsafe { slice::from_raw_parts(insn_ptr, count) };
        let insn_compare_zipped: Vec<(&(&[u8], &str, u32), &cs_insn)> =
            code.iter().zip(insns).collect();

        for &(&(bytes, mnemonic, ref id), insn) in insn_compare_zipped.iter() {
            let insn_mnemonic = convert_char_array_to_string(&insn.mnemonic);
            assert_eq!(insn_mnemonic, mnemonic);
            assert_eq!(insn.size as usize, bytes.len());
            assert_eq!(&insn.bytes[..insn.size as usize], bytes);
            assert_eq!(insn.address, address);
            assert_eq!(insn.id, *id);
            address += insn.size as u64;
        }

        // Close handle
        unsafe { cs_close(&mut handle as *mut csh) };
    }

    #[test]
    fn test_x86_disassembly() {
        let code: &[(&[u8], &str, _)] = &[
            (
                &[0x48, 0x83, 0xec, 0x08],
                "sub",
                x86_insn::X86_INS_SUB as u32,
            ),
            (&[0x31, 0xdb], "xor", x86_insn::X86_INS_XOR as u32),
            (&[0xc3], "ret", x86_insn::X86_INS_RET as u32),
            (&[0x90], "nop", x86_insn::X86_INS_NOP as u32),
        ];
        test_disassembly_helper(cs_arch::CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN, code);
    }

    #[test]
    fn test_evm_disassembly() {
        let code: &[(&[u8], &str, _)] = &[
            (&[0x60, 0x1], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0x54], "sload", evm_insn::EVM_INS_SLOAD as u32),
            (&[0x60, 0x0], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0x55], "sstore", evm_insn::EVM_INS_SSTORE as u32),
            (&[0x60, 0x0], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0x52], "mstore", evm_insn::EVM_INS_MSTORE as u32),
            (&[0x60, 0x20], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0x60, 0x0], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0xf3], "return", evm_insn::EVM_INS_RETURN as u32),
            (&[0x61, 0x0, 0x35], "push2", evm_insn::EVM_INS_PUSH2 as u32),
            (&[0x56], "jump", evm_insn::EVM_INS_JUMP as u32),
            (&[0x0], "stop", evm_insn::EVM_INS_STOP as u32),
            (&[0xff], "suicide", evm_insn::EVM_INS_SUICIDE as u32),
            (&[0x5b], "jumpdest", evm_insn::EVM_INS_JUMPDEST as u32),
            (&[0x60, 0x1], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0x60, 0xf4], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0x57], "jumpi", evm_insn::EVM_INS_JUMPI as u32),
            (&[0x60, 0xff], "push1", evm_insn::EVM_INS_PUSH1 as u32),
            (&[0x61, 0xff, 0xff], "push2", evm_insn::EVM_INS_PUSH2 as u32),
            (
                &[0x62, 0xff, 0xff, 0xff],
                "push3",
                evm_insn::EVM_INS_PUSH3 as u32,
            ),
            (
                &[0x63, 0xff, 0xff, 0xff, 0xff],
                "push4",
                evm_insn::EVM_INS_PUSH4 as u32,
            ),
            (
                &[0x64, 0xff, 0xff, 0xff, 0xff, 0xff],
                "push5",
                evm_insn::EVM_INS_PUSH5 as u32,
            ),
            (
                &[0x65, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "push6",
                evm_insn::EVM_INS_PUSH6 as u32,
            ),
            (
                &[0x66, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "push7",
                evm_insn::EVM_INS_PUSH7 as u32,
            ),
            (
                &[0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "push8",
                evm_insn::EVM_INS_PUSH8 as u32,
            ),
            (
                &[0x68, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "push9",
                evm_insn::EVM_INS_PUSH9 as u32,
            ),
            (
                &[
                    0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push10",
                evm_insn::EVM_INS_PUSH10 as u32,
            ),
            (
                &[
                    0x6a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push11",
                evm_insn::EVM_INS_PUSH11 as u32,
            ),
            (
                &[
                    0x6b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push12",
                evm_insn::EVM_INS_PUSH12 as u32,
            ),
            (
                &[
                    0x6c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff,
                ],
                "push13",
                evm_insn::EVM_INS_PUSH13 as u32,
            ),
            (
                &[
                    0x6d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff,
                ],
                "push14",
                evm_insn::EVM_INS_PUSH14 as u32,
            ),
            (
                &[
                    0x6e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                "push15",
                evm_insn::EVM_INS_PUSH15 as u32,
            ),
            (
                &[
                    0x6f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff,
                ],
                "push16",
                evm_insn::EVM_INS_PUSH16 as u32,
            ),
            (
                &[
                    0x70, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push17",
                evm_insn::EVM_INS_PUSH17 as u32,
            ),
            (
                &[
                    0x71, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push18",
                evm_insn::EVM_INS_PUSH18 as u32,
            ),
            (
                &[
                    0x72, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push19",
                evm_insn::EVM_INS_PUSH19 as u32,
            ),
            (
                &[
                    0x73, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push20",
                evm_insn::EVM_INS_PUSH20 as u32,
            ),
            (
                &[
                    0x74, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push21",
                evm_insn::EVM_INS_PUSH21 as u32,
            ),
            (
                &[
                    0x75, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push22",
                evm_insn::EVM_INS_PUSH22 as u32,
            ),
            (
                &[
                    0x76, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push23",
                evm_insn::EVM_INS_PUSH23 as u32,
            ),
            (
                &[
                    0x77, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push24",
                evm_insn::EVM_INS_PUSH24 as u32,
            ),
            (
                &[
                    0x78, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push25",
                evm_insn::EVM_INS_PUSH25 as u32,
            ),
            (
                &[
                    0x79, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff,
                ],
                "push26",
                evm_insn::EVM_INS_PUSH26 as u32,
            ),
            (
                &[
                    0x7a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff,
                ],
                "push27",
                evm_insn::EVM_INS_PUSH27 as u32,
            ),
            (
                &[
                    0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                "push28",
                evm_insn::EVM_INS_PUSH28 as u32,
            ),
            (
                &[
                    0x7c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff,
                ],
                "push29",
                evm_insn::EVM_INS_PUSH29 as u32,
            ),
            (
                &[
                    0x7d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push30",
                evm_insn::EVM_INS_PUSH30 as u32,
            ),
            (
                &[
                    0x7e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push31",
                evm_insn::EVM_INS_PUSH31 as u32,
            ),
            (
                &[
                    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                "push32",
                evm_insn::EVM_INS_PUSH32 as u32,
            ),
        ];
        test_disassembly_helper(cs_arch::CS_ARCH_EVM, cs_mode(0), code);
    }
}
