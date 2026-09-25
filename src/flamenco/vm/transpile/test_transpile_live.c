#include "fd_transpile_live.h"
#include "fd_transpile_runtime.h"
#include "../fd_vm_private.h"
#include "../../../ballet/murmur3/fd_murmur3.h"
#include "../../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../runtime/fd_runtime.h"
#include "../../runtime/fd_system_ids.h"
#include "../../runtime/sysvar/fd_sysvar_cache.h"
#include "../../log_collector/fd_log_collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* maps_perms looks up the /proc/self/maps entry containing addr and
   copies its permission string (e.g. "r-xp") to perms.  Returns 0 on
   success or -1 if addr is not mapped. */

static int
maps_perms( ulong addr,
            char  perms[5] ) {
  FILE * f = fopen( "/proc/self/maps", "r" );
  FD_TEST( f );
  char line[ 512 ];
  int  found = -1;
  while( fgets( line, sizeof(line), f ) ) {
    ulong lo, hi;
    char  p[5];
    if( sscanf( line, "%lx-%lx %4s", &lo, &hi, p )!=3 ) continue;
    if( addr>=lo && addr<hi ) {
      memcpy( perms, p, 5UL );
      found = 0;
      break;
    }
  }
  fclose( f );
  return found;
}

static void
check_mapping( ulong        addr,
               ulong        sz,
               char const * expected ) {
  for( ulong off=0UL; off<sz; off+=FD_SHMEM_NORMAL_PAGE_SZ ) {
    char perms[5];
    FD_TEST( !maps_perms( addr+off, perms ) );
    if( FD_UNLIKELY( strcmp( perms, expected ) ) ) {
      FD_LOG_ERR(( "mapping %#lx has perms %s, expected %s", addr+off, perms, expected ));
    }
  }
}

/* Test program (sBPF v0):
     0: call sol_memset_         (r3=0 => no-op, sets r0=0)
     1: mov64 r2, 1
     2: lsh64 r2, 32
     3: add64 r2, 8*8            (r2 = vaddr of pc 8)
     4: callx r2
     5: add64 r0, 1
     6: exit
     7: exit
     8: mov64 r0, 41
     9: exit
   Returns 42.  Exercises a syscall veneer and the callx tables. */

#define TEST_TEXT_CNT 10UL

static void
test_program( fd_sbpf_program_t * prog,
              ulong *             text,
              void *              calldests_mem ) {
  ulong callx_dst = 8UL;
  uint  memset_id = fd_murmur3_32( "sol_memset_", 11UL, 0U );
  text[0] = fd_vm_instr( FD_SBPF_OP_CALL_IMM,  0, 0, 0, memset_id );
  text[1] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2, 0, 0, 1U );
  text[2] = fd_vm_instr( FD_SBPF_OP_LSH64_IMM, 2, 0, 0, 32U );
  text[3] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 2, 0, 0, (uint)( callx_dst*8UL ) );
  text[4] = fd_vm_instr( FD_SBPF_OP_CALL_REG,  0, 0, 0, 2U );
  text[5] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 1U );
  text[6] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );
  text[7] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );
  text[8] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 0, 0, 0, 41U );
  text[9] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );

  fd_sbpf_calldests_t * calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, TEST_TEXT_CNT ) );
  FD_TEST( calldests );
  fd_sbpf_calldests_insert( calldests, 0UL       );
  fd_sbpf_calldests_insert( calldests, callx_dst );

  memset( prog, 0, sizeof(fd_sbpf_program_t) );
  prog->info.text_cnt     = (uint)TEST_TEXT_CNT;
  prog->info.text_sz      = TEST_TEXT_CNT*8UL;
  prog->info.sbpf_version = FD_SBPF_V0;
  prog->rodata            = text;
  prog->rodata_sz         = TEST_TEXT_CNT*8UL;
  prog->text              = text;
  prog->entry_pc          = 0UL;
  prog->calldests         = calldests;
}

static int
test_exec( fd_sbpf_program_t const *    prog,
           fd_sbpf_syscalls_t *         syscalls,
           fd_vm_transpiled_exec_func_t fn,
           ulong *                      cu ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  static fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  FD_TEST( fd_vm_init( vm, NULL, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, 0UL, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       NULL, 0UL, NULL, 0, 0, 0, 0, 0, 0UL ) );

  int err = fn ? fn( vm ) : fd_vm_exec( vm );
  FD_TEST( vm->reg[0]==42UL );
  *cu = vm->cu;

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
  return err;
}

/* sBPF program fixtures from the repo.  Each is loaded, executed by
   fd_vm_exec and by transpiled code, and the results compared. */

#define FIX(id,path) FD_IMPORT_BINARY( id, "src/ballet/sbpf/fixtures/" path )
FIX( fixture_hello,       "hello_solana_program.so" );
FIX( fixture_clock,       "clock_sysvar_program.so" );
FIX( fixture_spl_p_token, "spl_p_token.so"          );
#undef FIX

static struct {
  char const *  name;
  uchar const * bin;
  ulong const * bin_sz;
} const fixtures[] = {
  { "hello_solana_program", fixture_hello,       &fixture_hello_sz       },
  { "clock_sysvar_program", fixture_clock,       &fixture_clock_sz       },
  { "spl_p_token",          fixture_spl_p_token, &fixture_spl_p_token_sz },
  {0}
};

/* Minimal runtime environment for syscalls: log collector, clock
   sysvar, instruction stack depth, and error reporting. */

typedef struct {
  fd_runtime_t *      runtime;
  fd_txn_out_t *      txn_out;
  fd_bank_t *         bank;
  fd_sysvar_cache_t * sysvar_cache;
  fd_log_collector_t  log[1];
  fd_instr_info_t     instr[1];
  fd_exec_instr_ctx_t instr_ctx[1];
} test_env_t;

static void
test_env_init( test_env_t * env ) {
  env->runtime      = calloc( 1UL, sizeof(fd_runtime_t) );
  env->txn_out      = calloc( 1UL, sizeof(fd_txn_out_t) );
  env->bank         = calloc( 1UL, sizeof(fd_bank_t)    );
  FD_TEST( env->runtime && env->txn_out && env->bank );
  static fd_sysvar_cache_t cache_mem[1];
  env->sysvar_cache = fd_sysvar_cache_join( fd_sysvar_cache_new( cache_mem ) );
  FD_TEST( env->sysvar_cache );

  fd_sol_sysvar_clock_t clock = {
    .slot                  = 1234UL,
    .epoch_start_timestamp = 1700000000L,
    .epoch                 = 5UL,
    .leader_schedule_epoch = 6UL,
    .unix_timestamp        = 1700000400L
  };
  fd_sysvar_cache_restore_one( env->sysvar_cache, &fd_sysvar_clock_id, 1UL, (uchar const *)&clock, sizeof(clock) );

  fd_features_disable_all( &env->bank->f.features );
  env->runtime->log.log_collector = env->log;
  env->runtime->instr.stack_sz    = 1;
  env->txn_out->accounts.cnt      = 1; /* program id: zero pubkey */

  memset( env->instr, 0, sizeof(fd_instr_info_t) );
  env->instr->stack_height = 1;

  memset( env->instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  env->instr_ctx->instr        = env->instr;
  env->instr_ctx->runtime      = env->runtime;
  env->instr_ctx->txn_out      = env->txn_out;
  env->instr_ctx->bank         = env->bank;
  env->instr_ctx->sysvar_cache = env->sysvar_cache;
  strcpy( env->instr_ctx->program_id_base58, "11111111111111111111111111111111" );
}

static void
test_env_fini( test_env_t * env ) {
  fd_sysvar_cache_delete( fd_sysvar_cache_leave( env->sysvar_cache ) );
  free( env->bank );
  free( env->txn_out );
  free( env->runtime );
}

typedef struct {
  int   err;
  ulong bail_cnt;
  ulong r0;
  ulong cu;
  ulong log_sz;
  uchar log[ FD_LOG_COLLECTOR_MAX + FD_LOG_COLLECTOR_EXTRA ];
} test_result_t;

static void
fixture_exec( test_env_t *                 env,
              fd_sbpf_program_t const *    prog,
              fd_sbpf_syscalls_t *         syscalls,
              fd_vm_transpiled_exec_func_t fn,
              test_result_t *              out ) {
  fd_log_collector_init( env->log, 1 );
  memset( &env->txn_out->err, 0, sizeof(env->txn_out->err) );
  memset( &env->txn_out->details.return_data, 0, sizeof(env->txn_out->details.return_data) );

  /* Serialized input: no accounts, empty instruction data, zero
     program id */
  static uchar input[ 64 ] __attribute__((aligned(16)));
  memset( input, 0, sizeof(input) );
  fd_vm_input_region_t region = {
    .haddr                  = (ulong)input,
    .region_sz              = (uint)sizeof(input),
    .address_space_reserved = sizeof(input),
    .is_writable            = 1
  };

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  static fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  FD_TEST( fd_vm_init( vm, env->instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, prog->info.text_off, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       &region, 1UL, NULL, 0, 0, 0, 0, 0, 0UL ) );
  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

  out->bail_cnt = 0UL;
  if( fn ) {
    out->err = fn( vm );
    if( out->err==FD_VM_ERR_BAIL ) {
      out->bail_cnt++;
      out->err = fd_vm_exec( vm );
    }
  } else {
    out->err = fd_vm_exec( vm );
  }
  out->r0     = vm->reg[0];
  out->cu     = vm->cu;
  out->log_sz = env->log->buf_sz;
  memcpy( out->log, env->log->buf, out->log_sz );

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

static void
test_fixtures( fd_sbpf_syscalls_t * syscalls ) {
  test_env_t env[1];
  test_env_init( env );
  static test_result_t res_interp[1];
  static test_result_t res_live  [1];

  fd_sbpf_loader_config_t config = {
    .elf_deploy_checks = 0,
    .sbpf_min_version  = FD_SBPF_V0,
    .sbpf_max_version  = FD_SBPF_V3
  };

  for( ulong i=0UL; fixtures[i].name; i++ ) {
    uchar const * bin    = fixtures[i].bin;
    ulong         bin_sz = *fixtures[i].bin_sz;

    fd_sbpf_elf_info_t info;
    FD_TEST( !fd_sbpf_elf_peek( &info, bin, bin_sz, &config ) );
    void * rodata   = aligned_alloc( FD_SBPF_PROG_RODATA_ALIGN, fd_ulong_align_up( fd_ulong_max( info.bin_sz, 1UL ), FD_SBPF_PROG_RODATA_ALIGN ) );
    void * prog_mem = aligned_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) );
    void * scratch  = malloc( bin_sz );
    FD_TEST( rodata && prog_mem && scratch );
    fd_sbpf_program_t * prog = fd_sbpf_program_new( prog_mem, &info, rodata );
    FD_TEST( prog );
    FD_TEST( !fd_sbpf_program_load( prog, bin, bin_sz, syscalls, &config, scratch, bin_sz ) );

    fd_transpiled_live_t * live = fd_transpiled_live_create( prog );
    FD_TEST( live );

    fixture_exec( env, prog, syscalls, NULL, res_interp );
    fixture_exec( env, prog, syscalls, (fd_vm_transpiled_exec_func_t)live->text_haddr, res_live );

    if( FD_UNLIKELY( res_interp->err!=res_live->err ||
                     res_interp->r0 !=res_live->r0  ||
                     res_interp->cu !=res_live->cu  ||
                     res_interp->log_sz!=res_live->log_sz ||
                     memcmp( res_interp->log, res_live->log, res_interp->log_sz ) ) ) {
      FD_LOG_ERR(( "%s: mismatch (interp err %d r0 %#lx cu %lu log_sz %lu) (live err %d r0 %#lx cu %lu log_sz %lu)",
                   fixtures[i].name,
                   res_interp->err, res_interp->r0, res_interp->cu, res_interp->log_sz,
                   res_live->err,   res_live->r0,   res_live->cu,   res_live->log_sz ));
    }
    FD_LOG_NOTICE(( "%s: ok (err %d r0 %#lx cu %lu log_sz %lu bail %lu)",
                    fixtures[i].name, res_live->err, res_live->r0, res_live->cu, res_live->log_sz, res_live->bail_cnt ));

    fd_transpiled_live_destroy( live );
    free( scratch );
    free( prog_mem );
    free( rodata );
  }

  test_env_fini( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static ulong text[ TEST_TEXT_CNT ];
  static fd_sbpf_program_t prog[1];
  void * calldests_mem = aligned_alloc( fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( TEST_TEXT_CNT ) );
  FD_TEST( calldests_mem );
  test_program( prog, text, calldests_mem );

  static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  FD_TEST( syscalls );
  FD_TEST( !fd_vm_syscall_register_all( syscalls, 0 ) );

  FD_TEST( !fd_transpiled_live_create( NULL ) );
  fd_transpiled_live_destroy( NULL );

  fd_transpiled_live_t * live = fd_transpiled_live_create( prog );
  FD_TEST( live );

  /* Layout and permissions */

  ulong text_lo   = live->text_haddr;
  ulong rodata_lo = live->rodata_haddr;
  FD_TEST( fd_ulong_is_aligned( text_lo,            FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( rodata_lo,          FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( live->text_map_sz,   FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( live->rodata_map_sz, FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( (ulong)live==rodata_lo );
  FD_TEST( text_lo+live->text_map_sz<=rodata_lo || rodata_lo+live->rodata_map_sz<=text_lo );
  long gap = (long)text_lo - (long)rodata_lo;
  FD_TEST( gap<(long)INT_MAX && gap>(long)INT_MIN );
  check_mapping( text_lo,   live->text_map_sz,   "r-xp" );
  check_mapping( rodata_lo, live->rodata_map_sz, "r--p" );

  /* Execution matches the interpreter */

  ulong cu_interp, cu_live;
  FD_TEST( test_exec( prog, syscalls, NULL, &cu_interp )==FD_VM_SUCCESS );
  FD_TEST( test_exec( prog, syscalls, (fd_vm_transpiled_exec_func_t)live->text_haddr, &cu_live )==FD_VM_SUCCESS );
  if( FD_UNLIKELY( cu_interp!=cu_live ) ) FD_LOG_ERR(( "cu mismatch: interp %lu, live %lu", cu_interp, cu_live ));

  /* Placement is randomized */

  ulong gap_cnt = 0UL;
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_transpiled_live_t * live2 = fd_transpiled_live_create( prog );
    FD_TEST( live2 );
    if( (long)live2->text_haddr - (long)live2->rodata_haddr != gap ) gap_cnt++;
    fd_transpiled_live_destroy( live2 );
  }
  FD_TEST( gap_cnt>0UL );

  fd_transpiled_live_destroy( live );
  char perms[5];
  FD_TEST( maps_perms( text_lo,   perms ) );
  FD_TEST( maps_perms( rodata_lo, perms ) );

  test_fixtures( syscalls );

  fd_sbpf_syscalls_delete( fd_sbpf_syscalls_leave( syscalls ) );
  free( calldests_mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
