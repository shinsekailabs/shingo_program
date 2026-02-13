use anchor_lang::prelude::Pubkey;
use anchor_lang::prelude::*;
use anchor_lang::system_program;
use arcium_anchor::prelude::*;

use default_env::default_env;
use solana_security_txt::security_txt;

// Map
// - Security txt file
// - Constants
// - Error codes
// - Accounts and types
// - Events
// - Anchor contexts
//  Anchor context : Trader
//  Anchor context : Season
//  Anchor context : Signal
// - Arcium instructions
//   Decrypt Signal
//   Reveal Signal
// - Program
// ------------------------

security_txt! {
    // Required fields
    name: "shingo_program",
    project_url: "https://shingo.finance",
    contacts: "email:knoll-clear-gout@duck.com",
    policy: "https://github.com/solana-labs/solana/blob/master/SECURITY.md",

    // Optional Fields
    preferred_languages: "en,fr",
    source_code: "https://github.com/Neal-C/shingo_program",
    source_release: default_env!("GITHUB_REF_NAME", "main"),
    source_tag: "v0.0.1",
    encryption: "
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Comment: Neal-C's OpenPGP certificate

mQINBGk2us0BEAC8FolNCixLEKkCABWcsBZRoz416/P/rgNetFYlrintZuh4jP/d
/+9nwNPSPho+l6KXpCtM18wwVAc6NsOso43yc42HFnLBdmUikDesMZk88Y9TBrNj
vpt11Q+NBkVJg1tH9XDSESEIAAvaLejGQ+BeBVZ55E+pMSYqDPSR3unK6QH368re
GhUqzbrfXhq2I9PHZp11YQ1DQdx4A7TGJCaw5Kyyc8kBgrbGl6nTu02iRDeSeF/E
tE6Uomh+XPm7by20F5RupiZ7P4HvpSq0d9cLh6g9rhaKV3whFgc8oKgEY7GSU5rI
/Ig7C3JeBFouKuQSr3Pq0BktKBFYPFsv40V3c9h4H0CWO8AYYiR/VMbJolw6mM3l
Upbnax+DP78dJmL/RVLYxoQ8dSYkThU1z44o6qgDbeYXlF2bX+NypWvz3lUw1ieT
NO0FZBcrPPjSkfXa/fFXppPNkxGBlJHYP+yoKiA44dEHOdk6iKweE+GpzkyWhPvW
9m0hsIQ1rBOsSF1MDmPxjILB2OtKtJD/zYXW1tuXIV+p2iEPzxDwxLUIwMijK8UR
R/sdFlLQwea9n1avrkOzpewVVrfS/Sa0bfaTNo1XTB/fopWDYGG66+vpW05ICtCO
LSDDBAWdl/uadDxFRj7MUh0EFvo2AGH6iVN0oEtZwMfnMu9p87YWgL/GqwARAQAB
tCJOZWFsLUMgPGtub2xsLWNsZWFyLWdvdXRAZHVjay5jb20+iQJXBBMBCgBBFiEE
xA0I0BDzuJRq54Dp17+QR24QWMkFAmk2us0CGwMFCQWjmoAFCwkIBwICIgIGFQoJ
CAsCBBYCAwECHgcCF4AACgkQ17+QR24QWMmmMA//cKEM/V6THdE14WD/HmTa0Sn6
2Ui+FafchIR8YN6q0IonFSPeBkZxuOI3n6b6dTcUK4H3WXM6s6goCts1qN8XrDrg
qxZCsJHVsqMw1cYijhk+PZNrpBT17jO7hSDBkq/pl4ZkJ3auxZS5a0EGVzTR2Qf6
pHMyH+Wup/9zYh38jf4zPV9kB1ZIwRix/hWJ2yyJr/o+EwMnIlpWJ0aFakEwPtoP
Zut0Ed5nRlNNe/9sCeczQbizvdqn+eEZN7WrDjZFHwXg4gy6DE/DHA2r71yDFjHV
4kg2mvYsnd2S7KFWFHsftkpruKeB9EIGnjjPWnBcRjP0i5ekqQw+/OFIwycX0fa/
j++QTLgSwE2QosL0ueXjFSzU9o1G569I0+OmbF1J/znZg2o47iQw1Pibndkwx+vZ
COZiRlYHUzAFn+B/kMSdhlI6yVdeJXuJs+TddE4VtocBsCklufG3XsfuSULasnkF
3iqktfHoce497f+FcFoDO9ulyfXHN2aJzDReqQJb2i/NdOpJgaNeo7EPtShVJNvE
ceK+u23wYYtBYdpK4M7lBrGwQEQG3scgXBoxcqAgb8rz/W2WAG/5e9y8qk3y8S66
ZkyF/3WSAv6kF3ByguiguIb1Es7I5tdjXipQaF3lvt4M/tFQVWHzgUr25W0iir0u
tjHQToczCXVWM+/r0FE=
=x+e2
-----END PGP PUBLIC KEY BLOCK-----
",
    auditors: "Ourselves and that's more than enough",
    acknowledgements: "
The following hackers could've stolen all our money but didn't:
- Jojo
- Neal-C
- https://shingo.finance/hall-of-fame
"
}

declare_id!("BsW6tsgxPVpdCeSwMdmtDiVdkVZspAT7Rd6DyW2o2iTj");

pub const DEVELOPER_ADDRESS: Pubkey = pubkey!("HhEBDdSK7ywsesAFdMcsQjWiWVBTYbjS386TJAVibMJQ");

/// This constant identifies our encrypted instruction for on-chain operations.
///
/// ``comp_def_offset()`` generates a unique identifier from the function name
pub const COMP_DEF_OFFSET_SIGNAL: u32 = comp_def_offset("decrypt_signal");

/// This constant identifies our encrypted instruction for on-chain operations.
/// ``comp_def_offset()`` generates a unique identifier from the function name
pub const COMP_DEF_OFFSET_REVEAL_SIGNAL: u32 = comp_def_offset("reveal_signal");

// ############# Error codes ###############

#[error_code]
pub enum ShingoProgramError {
    #[msg("Not Subbed")]
    NotSubbed,
    #[msg("Nope")]
    Nono,
    #[msg("The computation was aborted")]
    AbortedComputation,
    #[msg("subscription failed")]
    SubscriptionFailed,
    #[msg("invalid subscription price")]
    InvalidSubscriptionPrice,
    #[msg("Checked Arithmetic failure")]
    CheckedArithmeticFailure,
    #[msg("LookupTable Deserialization failure")]
    LookupTableDeserializationFailure,
    #[msg("Casting failure")]
    CastingFailure,
    #[msg("Bytemuck failure")]
    BytemuckFailure,
    #[msg("Cannot create new season while there's an active season. Close current season first")]
    CannotCreateNewSeasonWhileHasActiveSeason,
    #[msg("Cannot close a season while there's no active season. Create a season first")]
    CannotCloseSeasonWhileNoActiveSeason,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Cluster not set")]
    ClusterNotSet,
}

// ############# Accounts and types ###############

#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub struct ProfitPoint {
    pub price: u64,
    pub size_pourcentage: u64,
}

#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub struct Market {
    pub left: [u8; 16],
    pub right: [u8; 16],
}

#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub struct Entry {
    pub kind: u8,
    pub price: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Signal {
    pub version: u8,
    pub id: [u8; 16],
    pub market: [[u8; 32]; 2],
    pub side: [u8; 32],
    pub entry: [[u8; 32]; 2],
    pub stop_loss: [u8; 32],
    pub profit_points: [[u8; 32]; 2],
    pub size_usd: [u8; 32],
    pub leverage: [u8; 32],
    pub venue: [u8; 32],
    pub timeframe: [u8; 32],
    pub season_id: u64,
    pub created_at: i64,
    pub number: u64,
}

impl Signal {
    pub const SEED: &'static [u8; 6] = b"signal";
}

#[account]
#[derive(InitSpace)]
pub struct TraderAccount {
    pub current_season: u64,
    pub has_active_season: bool,
    pub signal_count: u64,
}

impl TraderAccount {
    pub const SEED: &'static [u8; 6] = b"trader";
}

#[account]
#[derive(InitSpace)]
pub struct Season {
    pub subscription_price: u64,
    pub id: u64,
    pub is_active: bool,
    pub count: u64,
}

impl Season {
    pub const SEED: &'static [u8; 6] = b"season";
}

#[account]
#[derive(InitSpace)]
pub struct SubscriptionPass {
    pub owner: Pubkey,
}

impl SubscriptionPass {
    pub const SEED: &'static [u8; 17] = b"subscription_pass";
}

// ############# Events ###############

#[event]
pub struct ObservableSignal {
    pub nonce: [u8; 16],
    pub version: [u8; 32],
    pub id: [u8; 32],
    pub market: [[u8; 32]; 2],
    pub side: [u8; 32],
    pub entry: [[u8; 32]; 2],
    pub stop_loss: [u8; 32],
    pub profit_points: [[u8; 32]; 2],
    pub size_usd: [u8; 32],
    pub leverage: [u8; 32],
    pub venue: [u8; 32],
    pub timeframe: [u8; 32],
    pub season_id: [u8; 32],
    pub created_at: [u8; 32],
    pub number: [u8; 32],
}

#[event]
pub struct ClearSignal {
    pub version: u8,
    pub id: [u8; 16],
    pub market: Market,
    /// LONG = 0 | SHORT = 1
    pub side: u8,
    pub entry: Entry,
    pub stop_loss: u64,
    pub profit_points: ProfitPoint,
    pub size_usd: u64,
    pub leverage: u64,
    pub venue: u8,
    pub timeframe: u64,
    pub season_id: u64,
    pub created_at: i64,
    pub number: u64,
}

#[event]
pub struct NewSeason {
    pub trader_address: Pubkey,
    pub season_address: Pubkey,
    pub season: u64,
}

#[event]
pub struct NewSubscription {
    pub followee: Pubkey,
    pub follower: Pubkey,
    pub season: u64,
}

#[event]
pub struct SeasonFinale {
    pub trader: Pubkey,
    pub season: u64,
    pub last_episode: u64,
}

#[event]
pub struct NewTrader {
    pub public_key: Pubkey,
}

// ##########################################
// ######### Anchor Contexts     ############
// - InitialiazeTraderAccount
// - InitialiazeSeason
// - SubscribeToSeason
// - CloseSeason
// - EncryptSignal
// - DecryptSignal
// ##########################################

// ############## Trader #######################

#[derive(Accounts)]
pub struct InitializeTraderAccount<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(
        init_if_needed,
        payer = trader,
        space = 8 + TraderAccount::INIT_SPACE,
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump)]
    pub trader_account: Account<'info, TraderAccount>,
}

// ################# Season ##################

#[derive(Accounts)]
pub struct InitialiazeSeason<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(
        init,
        payer = trader,
        space = 8 + SubscriptionPass::INIT_SPACE,
        seeds = [SubscriptionPass::SEED, DEVELOPER_ADDRESS.to_bytes().as_ref(), trader.key().as_ref(),trader_account.current_season.checked_add(1).unwrap_or(trader_account.current_season).to_le_bytes().as_ref()],
        bump
    )]
    pub shingo_pass: Account<'info, SubscriptionPass>,

    #[account(
        init,
        payer = trader,
        space = 8 + SubscriptionPass::INIT_SPACE,
        seeds = [SubscriptionPass::SEED, trader.key().as_ref() ,trader.key().as_ref(), trader_account.current_season.checked_add(1).unwrap_or(trader_account.current_season).to_le_bytes().as_ref()],
        bump
    )]
    pub trader_pass: Account<'info, SubscriptionPass>,

    #[account(mut)]
    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        init,
        payer = trader,
        space = 8 + Season::INIT_SPACE,
        // has to be on 1 line
        seeds = [Season::SEED, trader.key().as_ref(), trader_account.current_season.checked_add(1).unwrap_or(trader_account.current_season).to_le_bytes().as_ref()],
        bump)]
    pub season: Account<'info, Season>,
}

#[derive(Accounts)]
pub struct SubscribeToSeason<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub follower: Signer<'info>,

    #[account(
        init,
        payer = follower,
        space = 8 + SubscriptionPass::INIT_SPACE,
        seeds = [SubscriptionPass::SEED, follower.key().as_ref() ,trader.key().as_ref(), trader_account.current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub follower_pass: Account<'info, SubscriptionPass>,

    #[account(mut)]
    pub trader: SystemAccount<'info>,

    #[account(mut)]
    pub developer: SystemAccount<'info>,

    #[account(mut)]
    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        // has to be on 1 line
        seeds = [Season::SEED,trader.key().as_ref(), trader_account.current_season.to_le_bytes().as_ref()],
        bump)]
    pub season: Account<'info, Season>,
}

#[derive(Accounts)]
pub struct CloseSeason<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(mut)]
    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        // has to be on 1 line
        seeds = [Season::SEED, trader.key().as_ref(), trader_account.current_season.to_le_bytes().as_ref()],
        bump)]
    pub season: Account<'info, Season>,
}

// ################# Signal ##################

#[derive(Accounts)]
pub struct EncryptSignal<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    pub season: Account<'info, Season>,

    #[account(
        init_if_needed,
        payer = trader,
        space = 8 + Signal::INIT_SPACE,
        // has to be on 1 lineđ
        seeds = [Signal::SEED, trader.key().as_ref(), season.id.to_le_bytes().as_ref(), season.count.to_le_bytes().as_ref()], bump)]
    pub signal: Account<'info, Signal>,
}

// #################################################
// ################     Arcium       ###############
// #################################################

// ################     Decrypt signal       ###############

pub fn to_market<T: Copy + bytemuck::Pod>(input: &[T]) -> Option<[T; 2]> {
    bytemuck::try_cast_slice(input).ok()?.first().copied()
}

pub fn to_entry<T: Copy + bytemuck::Pod>(input: &[T]) -> Option<[T; 2]> {
    bytemuck::try_cast_slice(input).ok()?.first().copied()
}

pub fn to_profit_points<T: Copy + bytemuck::Pod>(input: &[T]) -> Option<[T; 2]> {
    bytemuck::try_cast_slice(input).ok()?.first().copied()
}

#[init_computation_definition_accounts("decrypt_signal", payer)]
#[derive(Accounts)]
pub struct InitDecryptSignalCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    #[account(mut)]
    /// CHECK: ``comp_def_account``, checked by arcium program.
    /// Can't check it here as it's not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,

    pub arcium_program: Program<'info, Arcium>,

    pub system_program: Program<'info, System>,

    // version 0.7.0 migration : new required accounts
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: ``address_lookup_table``, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,

    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: ``lut_program`` is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
}

#[queue_computation_accounts("decrypt_signal", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct DecryptSignal<'info> {
    pub season: Account<'info, Season>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub trader: SystemAccount<'info>,

    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SubscriptionPass::INIT_SPACE,
        seeds = [SubscriptionPass::SEED, payer.key().as_ref() ,trader.key().as_ref(), trader_account.current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub follower_pass: Account<'info, SubscriptionPass>,

    pub signal: Account<'info, Signal>,

    #[account(
    init_if_needed,
    payer = payer,
    space = 8 + 1,
    seeds = [b"ArciumSignerAccount"],
    bump,
    address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,

    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,

    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: ``mempool_account``, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,

    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: ``executing_pool``, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,

    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: ``computation_account``, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,

    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_SIGNAL)
    )]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,

    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    pub cluster_account: Account<'info, Cluster>,

    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,

    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,

    pub system_program: Program<'info, System>,

    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("decrypt_signal")]
#[derive(Accounts)]
pub struct DecryptSignalCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,

    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_SIGNAL)
    )]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,

    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Account<'info, MXEAccount>,

    /// CHECK: ``computation_account``, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,

    #[account(
        address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    pub cluster_account: Account<'info, Cluster>,

    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: ``instructions_sysvar``, checked by the account constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

// ################     Reveal signal       ###############

#[init_computation_definition_accounts("reveal_signal", payer)]
#[derive(Accounts)]
pub struct InitRevealSignalCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    #[account(mut)]
    /// CHECK: ``comp_def_account``, checked by arcium program.
    /// Can't check it here as it's not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,

    pub arcium_program: Program<'info, Arcium>,

    pub system_program: Program<'info, System>,

    // version 0.7.0 migration : new required accounts
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: ``address_lookup_table``, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,

    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: ``lut_program`` is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
}

#[queue_computation_accounts("reveal_signal", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct RevealSignal<'info> {
    pub season: Account<'info, Season>,

    pub signal: Account<'info, Signal>,

    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
    init_if_needed,
    payer = payer,
    space = 8 + 1,
    seeds = [b"ArciumSignerAccount"],
    bump,
    address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,

    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: ``mempool_account``, checked by the arcium program
    pub mempool_account: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: ``executing_pool``, checked by the arcium program
    pub executing_pool: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: ``computation_account``, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_REVEAL_SIGNAL)
    )]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    pub cluster_account: Account<'info, Cluster>,
    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,
    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("reveal_signal")]
#[derive(Accounts)]
pub struct RevealSignalCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,

    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_REVEAL_SIGNAL)
    )]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,

    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Account<'info, MXEAccount>,

    /// CHECK: ``computation_account``, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,

    #[account(
        address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    pub cluster_account: Account<'info, Cluster>,

    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: ``instructions_sysvar``, checked by the account constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

// ###################################
// ############# PROGRAM #############
// ###################################

#[arcium_program]
pub mod shingo_program {

    #[allow(clippy::wildcard_imports)]
    use super::*;

    // Map
    // ########## Trader ###########
    // ########## Trader : initialize_trader_account
    // ########## Season ###########
    // ########## Season:  initialize_season
    // ########## Season:  subscribe_to_season
    // ########## Season:  close_season
    // ########## Signal ###########
    // ######### Arcium ############
    // ######### Arcium : encrypt_signal
    // ######### Arcium : reveal_signal
    // --------------------------------------------------------------

    // ########## Trader ###########

    /// # Errors
    /// Cannot error
    /// Called Once by the trader
    pub fn initialize_trader_account(ctx: Context<InitializeTraderAccount>) -> Result<()> {
        let trader_account = &mut ctx.accounts.trader_account;

        if trader_account.to_account_info().data_len() > 0 {
            return Ok(());
        }

        trader_account.current_season = 0;
        trader_account.has_active_season = false;
        trader_account.signal_count = 0;

        emit!(NewTrader {
            public_key: ctx.accounts.trader.key()
        });

        Ok(())
    }

    // ########## Season ###########

    /// # Errors
    /// Theoritically may have an arithemic error that cause Overflow Error
    /// Called multiple times by the trader, at start of a new season
    /// Errors if ``subscription_price`` is equal to 0
    /// Errors if the followers extending invoke fails
    pub fn initialize_season(
        ctx: Context<InitialiazeSeason>,
        subscription_price: u64,
    ) -> Result<()> {
        require!(
            subscription_price != 0,
            ShingoProgramError::InvalidSubscriptionPrice
        );

        require!(
            !ctx.accounts.trader_account.has_active_season,
            ShingoProgramError::CannotCreateNewSeasonWhileHasActiveSeason
        );

        let trader_account = &mut ctx.accounts.trader_account;
        let season_number = trader_account
            .current_season
            .checked_add(1)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        trader_account.current_season = season_number;
        trader_account.signal_count = 0;
        trader_account.has_active_season = true;

        let season = &mut ctx.accounts.season;
        season.subscription_price = subscription_price;
        season.id = season_number;
        season.is_active = true;
        season.count = 0;

        let shingo_pass = &mut ctx.accounts.shingo_pass;
        shingo_pass.owner = DEVELOPER_ADDRESS;

        let trader_pass = &mut ctx.accounts.trader_pass;
        trader_pass.owner = ctx.accounts.trader.key();

        emit!(NewSeason {
            trader_address: ctx.accounts.trader.key(),
            season_address: ctx.accounts.season.key(),
            season: season_number,
        });

        Ok(())
    }

    /// # Errors
    /// May fail on transfers.
    /// Errors if the followers extending invoke fails
    pub fn subscribe_to_season(ctx: Context<SubscribeToSeason>) -> Result<()> {
        let developer = &ctx.accounts.developer;

        require!(
            developer.key().eq(&DEVELOPER_ADDRESS),
            ShingoProgramError::Nono
        );

        let price = ctx.accounts.season.subscription_price;

        let tip = price
            .checked_div(100)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.follower.to_account_info(),
                    to: ctx.accounts.developer.to_account_info(),
                },
            ),
            tip,
        )?;

        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.follower.to_account_info(),
                    to: ctx.accounts.trader.to_account_info(),
                },
            ),
            price,
        )?;

        let follower_pass = &mut ctx.accounts.follower_pass;
        follower_pass.owner = ctx.accounts.follower.key();

        emit!(NewSubscription {
            followee: ctx.accounts.trader.key(),
            follower: ctx.accounts.follower.key(),
            season: ctx.accounts.season.id
        });

        Ok(())
    }

    /// # Errors
    /// Theoritically may have an arithemic error that cause Overflow
    /// Called multiple times by the trader, at the end a season
    /// Ending a season makes all its signals decryptable by everyone
    pub fn close_season(ctx: Context<CloseSeason>) -> Result<()> {
        require!(
            ctx.accounts.trader_account.has_active_season,
            ShingoProgramError::CannotCloseSeasonWhileNoActiveSeason
        );
        let trader_account = &mut ctx.accounts.trader_account;
        trader_account.has_active_season = false;
        trader_account.signal_count = 0;

        let season = &mut ctx.accounts.season;
        season.is_active = false;

        emit!(SeasonFinale {
            trader: ctx.accounts.trader.key(),
            season: ctx.accounts.season.id,
            last_episode: ctx.accounts.season.count,
        });

        Ok(())
    }

    // ########## Signal ###########

    /// # Errors
    /// Can error on safe arithmetic addition failure
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_signal(
        ctx: Context<EncryptSignal>,
        version: u8,
        id: [u8; 16],
        market: [[u8; 32]; 2],
        side: [u8; 32],
        entry: [[u8; 32]; 2],
        stop_loss: [u8; 32],
        profit_points: [[u8; 32]; 2],
        size_usd: [u8; 32],
        leverage: [u8; 32],
        venue: [u8; 32],
        timeframe: [u8; 32],
    ) -> Result<()> {
        let signal = &mut ctx.accounts.signal;

        signal.version = version;
        signal.id = id;
        signal.market = market;
        signal.side = side;
        signal.entry = entry;
        signal.stop_loss = stop_loss;
        signal.profit_points = profit_points;
        signal.size_usd = size_usd;
        signal.leverage = leverage;
        signal.venue = venue;
        signal.timeframe = timeframe;
        signal.season_id = ctx.accounts.season.id;
        signal.created_at = Clock::get()?.unix_timestamp;
        signal.number = ctx.accounts.season.count;

        let season = &mut ctx.accounts.season;

        let new_count = season
            .count
            .checked_add(1)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        season.count = new_count;

        Ok(())
    }

    // ######### Arcium : encrypt_signal ########

    /// # Errors
    /// Cannot error, fn just initializes the ``comp_def``
    /// Called once by the admin
    pub fn init_decrypt_signal_comp_def(ctx: Context<InitDecryptSignalCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    /// # Errors
    /// Errors if ``queue_computation`` fails
    pub fn decrypt_signal(
        ctx: Context<DecryptSignal>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
        sender_pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let follower_pass = &ctx.accounts.follower_pass;

        let owner = follower_pass.owner;

        require!(
            owner.eq(ctx.accounts.payer.key),
            ShingoProgramError::NotSubbed
        );
        // --------------------------------------
        let init_space: u32 = Signal::INIT_SPACE
            .try_into()
            .map_err(|_| ShingoProgramError::CastingFailure)?;

        let args = ArgBuilder::new()
            .x25519_pubkey(receiver)
            .plaintext_u128(receiver_nonce)
            .x25519_pubkey(sender_pub_key)
            .plaintext_u128(nonce)
            .account(ctx.accounts.signal.key(), 8, init_space)
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![DecryptSignalCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[],
            )?],
            1,
            0,
        )?;

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "decrypt_signal")]
    pub fn decrypt_signal_callback(
        ctx: Context<DecryptSignalCallback>,
        output: SignedComputationOutputs<DecryptSignalOutput>,
    ) -> Result<()> {
        let Ok(DecryptSignalOutput { field_0: my_output }) = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) else {
            return Err(ShingoProgramError::AbortedComputation.into());
        };

        let version = my_output.ciphertexts[0];

        let id = my_output.ciphertexts[1];

        let market = {
            let market = &my_output.ciphertexts[2..4];
            let market = to_market(market).ok_or(ShingoProgramError::BytemuckFailure)?;
            market
        };

        let side = my_output.ciphertexts[4];

        let entry =
            to_entry(&my_output.ciphertexts[5..7]).ok_or(ShingoProgramError::BytemuckFailure)?;

        let stop_loss = my_output.ciphertexts[7];

        let profit_points = to_profit_points(&my_output.ciphertexts[8..10])
            .ok_or(ShingoProgramError::BytemuckFailure)?;

        let size_usd = my_output.ciphertexts[10];

        let leverage = my_output.ciphertexts[11];

        let venue = my_output.ciphertexts[12];

        let timeframe = my_output.ciphertexts[13];

        let season_id = my_output.ciphertexts[14];

        let created_at = my_output.ciphertexts[15];

        let number = my_output.ciphertexts[16];

        emit!(ObservableSignal {
            nonce: my_output.nonce.to_le_bytes(),
            version,
            id,
            market,
            side,
            entry,
            stop_loss,
            profit_points,
            size_usd,
            leverage,
            venue,
            timeframe,
            season_id,
            created_at,
            number,
        });

        Ok(())
    }

    // ######### Arcium : reveal_signal     ########

    /// # Errors
    /// Cannot fail
    /// Called once by the admin
    pub fn init_reveal_signal_comp_def(ctx: Context<InitRevealSignalCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    /// # Errors
    /// Errors if ``queue_computation`` fails
    pub fn reveal_signal(ctx: Context<RevealSignal>, computation_offset: u64) -> Result<()> {
        require!(
            (ctx.accounts.season.id == ctx.accounts.signal.season_id)
                && !ctx.accounts.season.is_active,
            ShingoProgramError::Nono
        );
        // --------------------------------------
        let init_space: u32 = Signal::INIT_SPACE
            .try_into()
            .map_err(|_| ShingoProgramError::CastingFailure)?;

        let args = ArgBuilder::new()
            .account(ctx.accounts.signal.key(), 8, init_space)
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![RevealSignalCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[],
            )?],
            1,
            0,
        )?;

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "reveal_signal")]
    pub fn reveal_signal_callback(
        ctx: Context<RevealSignalCallback>,
        output: SignedComputationOutputs<RevealSignalOutput>,
    ) -> Result<()> {
        let Ok(RevealSignalOutput { field_0: my_output }) = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) else {
            return Err(ShingoProgramError::AbortedComputation.into());
        };

        emit!(ClearSignal {
            version: my_output.field_0,
            id: my_output.field_1,
            market: Market {
                left: my_output.field_2.field_0,
                right: my_output.field_2.field_1
            },
            side: my_output.field_3,
            entry: Entry {
                kind: my_output.field_4.field_0,
                price: my_output.field_4.field_1
            },
            stop_loss: my_output.field_5,
            profit_points: ProfitPoint {
                price: my_output.field_6.field_0,
                size_pourcentage: my_output.field_6.field_1
            },
            size_usd: my_output.field_7,
            leverage: my_output.field_8,
            venue: my_output.field_9,
            timeframe: my_output.field_10,
            season_id: my_output.field_11,
            created_at: my_output.field_12,
            number: my_output.field_13
        });

        Ok(())
    }
}
