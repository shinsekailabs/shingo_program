#![allow(clippy::diverging_sub_expression)]

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
    source_code: "https://github.com/shinsekailabs/shingo_program",
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
    auditors: "webrainsec, EagleEye, Oxfindings",
    acknowledgements: "
The following hackers could've stolen all our money but didn't:
- webrainsec
- EagleEye
- Oxfindings
- https://shingo.finance/hall-of-fame
"
}

declare_id!("HMGBKT1i1pJsaoQqcHXQGVb8FAbg8taPSCbKVLhnDTyY");

pub const DEVELOPER_ADDRESS: Pubkey = pubkey!("HhEBDdSK7ywsesAFdMcsQjWiWVBTYbjS386TJAVibMJQ");

/// This constant identifies our encrypted instruction for on-chain operations.
/// ``comp_def_offset()`` generates a unique identifier from the function name
pub const COMP_DEF_OFFSET_DECRYPT_SIGNAL: u32 = comp_def_offset("decrypt_signal");

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
    #[msg("This season has reached its maximum number of subscribers")]
    SeasonMaximumSubscribersNumberReached,
    #[msg("Cannot close a season until it reaches its minimum number of episodes")]
    CannotCloseSeasonUntilMinimumNumberOfEpisodesIsReached,
    #[msg("This signal cannot be revealed because its season is not finished")]
    SignalCannotBeRevealedBecauseItsSeasonNotFinished,
    #[msg("Season is inactive")]
    SeasonIsInactive,
    #[msg("Sus")]
    Sus,
}

// ############# Accounts and types ###############

/// Ticker
///
/// SOL = 1
///
/// BTC = 2
///
/// ETH = 3
///
/// USDS (USD Sky / DAI new name) = 4
///
/// USDT = 5
///
/// USDC = 6
///
/// JupUSD = 7
///
/// EURC = 8
///
/// USDG = 9
///
/// PyUSD = 10
///
/// hyUSD = 11
pub type Ticker = u64;

#[derive(AnchorDeserialize, AnchorSerialize, Clone, InitSpace)]
pub struct Metadata {
    pub season_id: u64,
    pub number: u64,
    pub created_at: i64,
    pub author: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct Signal {
    pub metadata: Metadata,
    pub market_left: [u8; 32],
    pub market_right: [u8; 32],
    pub side: [u8; 32],
    pub entry_kind: [u8; 32],
    pub entry_price: [u8; 32],
    pub stop_loss: [u8; 32],
    pub profit_point_price: [u8; 32],
    pub profit_point_size_percentage: [u8; 32],
    pub size_usd: [u8; 32],
    pub leverage: [u8; 32],
    pub venue: [u8; 32],
    pub timeframe: [u8; 32],
}

impl Signal {
    pub const SEED: &'static [u8; 6] = b"signal";
    pub const ARCIUM_OFFSET: usize = 8 + Metadata::INIT_SPACE;
    pub const ARCIUM_INIT_SPACE: usize = Self::INIT_SPACE - Metadata::INIT_SPACE;
}

#[account]
#[derive(InitSpace)]
pub struct TraderAccount {
    pub current_season: u64,
    pub has_active_season: bool,
}

impl TraderAccount {
    pub const SEED: &'static [u8; 6] = b"trader";
}

#[account]
#[derive(InitSpace)]
pub struct Season {
    pub trader: Pubkey,
    pub subscription_price: u64,
    pub id: u64,
    pub is_active: bool,
    pub episodes: u64,
    pub minimum_number_of_episodes: u64,
    pub maximum_subscribers: u64,
    pub subscribers: u64,
    pub last_seen: i64,
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

#[account]
#[derive(InitSpace)]
pub struct ClaimPass {
    pub claimed: bool,
}

impl ClaimPass {
    pub const SEED: &'static [u8; 10] = b"claim_pass";
}

#[account]
#[derive(InitSpace)]
pub struct SeasonEscrow;

impl SeasonEscrow {
    pub const SEED: &'static [u8; 13] = b"season_escrow";
}

#[account]
#[derive(InitSpace)]
pub struct RevealedSignal {
    pub metadata: Metadata,
    pub market_left: u64,
    pub market_right: u64,
    /// LONG = 0 | SHORT = 1
    pub side: u64,
    pub entry_kind: u64,
    pub entry_price: u64,
    pub stop_loss: u64,
    pub profit_point_price: u64,
    pub profit_point_size_percentage: u64,
    pub size_usd: u64,
    pub leverage: u64,
    pub venue: u64,
    pub timeframe: u64,
}

impl RevealedSignal {
    pub const SEED: &'static [u8; 8] = b"revealed";
}

// ############# Events ###############

#[event]
pub struct ObservableSignal {
    pub nonce: [u8; 16],
    pub metadata: Metadata,
    pub market_left: [u8; 32],
    pub market_right: [u8; 32],
    pub side: [u8; 32],
    pub entry_kind: [u8; 32],
    pub entry_price: [u8; 32],
    pub stop_loss: [u8; 32],
    pub profit_point_price: [u8; 32],
    pub profit_point_size_percentage: [u8; 32],
    pub size_usd: [u8; 32],
    pub leverage: [u8; 32],
    pub venue: [u8; 32],
    pub timeframe: [u8; 32],
    pub requester: Pubkey,
}

#[event]
pub struct ClearSignal {
    pub metadata: Metadata,
    pub market_left: Ticker,
    pub market_right: Ticker,
    /// LONG = 0 | SHORT = 1
    pub side: u64,
    pub entry_kind: u64,
    pub entry_price: u64,
    pub stop_loss: u64,
    pub profit_point_price: u64,
    pub profit_point_size_percentage: u64,
    pub size_usd: u64,
    pub leverage: u64,
    pub venue: u64,
    pub timeframe: u64,
    pub requester: Pubkey,
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

#[event]
pub struct ForciblyClosedSeason {
    pub trader: Pubkey,
    pub season: u64,
}

#[event]
pub struct ComputationAborted {
    pub requester: Pubkey,
}

// ##########################################
// ######### Anchor Contexts     ############
// - InitializeTraderAccount
// - InitializeSeason
// - SubscribeToSeason
// - CloseSeason
// - EncryptSignal
// - DecryptSignal
// - RevealSignal
// ##########################################

// ############## Trader #######################

#[derive(Accounts)]
pub struct InitializeTraderAccount<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(
        init,
        payer = trader,
        space = 8 + TraderAccount::INIT_SPACE,
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump)]
    pub trader_account: Account<'info, TraderAccount>,
}

// ################# Season ##################

#[derive(Accounts)]
pub struct InitializeSeason<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(
        init,
        payer = trader,
        space = 8 + SeasonEscrow::INIT_SPACE,
        seeds = [SeasonEscrow::SEED, trader.key().as_ref(),trader_account.current_season.checked_add(1).ok_or(ShingoProgramError::CheckedArithmeticFailure)?.to_le_bytes().as_ref()],
        bump
    )]
    pub season_escrow: Account<'info, SeasonEscrow>,

    #[account(
        init,
        payer = trader,
        space = 8 + SubscriptionPass::INIT_SPACE,
        seeds = [SubscriptionPass::SEED, DEVELOPER_ADDRESS.to_bytes().as_ref(), trader.key().as_ref(),trader_account.current_season.checked_add(1).ok_or(ShingoProgramError::CheckedArithmeticFailure)?.to_le_bytes().as_ref()],
        bump
    )]
    pub shingo_pass: Account<'info, SubscriptionPass>,

    #[account(
        init,
        payer = trader,
        space = 8 + SubscriptionPass::INIT_SPACE,
        seeds = [SubscriptionPass::SEED, trader.key().as_ref() ,trader.key().as_ref(), trader_account.current_season.checked_add(1).ok_or(ShingoProgramError::CheckedArithmeticFailure)?.to_le_bytes().as_ref()],
        bump
    )]
    pub trader_pass: Account<'info, SubscriptionPass>,

    #[account(
        mut,
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump
    )]
    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        init,
        payer = trader,
        space = 8 + Season::INIT_SPACE,
        seeds = [Season::SEED, trader.key().as_ref(), trader_account.current_season.checked_add(1).ok_or(ShingoProgramError::CheckedArithmeticFailure)?.to_le_bytes().as_ref()],
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
    pub subscription_pass: Account<'info, SubscriptionPass>,

    #[account(
        mut,
        seeds = [SeasonEscrow::SEED, trader.key().as_ref(),trader_account.current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub season_escrow: Account<'info, SeasonEscrow>,

    #[account(mut)]
    pub trader: SystemAccount<'info>,

    #[account(mut)]
    pub developer: SystemAccount<'info>,

    #[account(
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump
    )]
    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        mut,
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

    #[account(
        mut,
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump
    )]
    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        mut,
        seeds = [Season::SEED, trader.key().as_ref(), trader_account.current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub season: Account<'info, Season>,

    #[account(
        mut,
        seeds = [SeasonEscrow::SEED, trader.key().as_ref(), trader_account.current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub season_escrow: Account<'info, SeasonEscrow>,
}

#[derive(Accounts)]
#[instruction(current_season: u64)]
pub struct ForceCloseSeason<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(
        mut,
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump
    )]
    pub trader_account: Account<'info, TraderAccount>,

    #[account(
        mut,
        seeds = [Season::SEED, trader.key().as_ref(), current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub season: Account<'info, Season>,

    #[account(
        mut,
        seeds = [SeasonEscrow::SEED, trader.key().as_ref(), current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub season_escrow: Account<'info, SeasonEscrow>,
}

#[derive(Accounts)]
#[instruction(season_id: u64)]
pub struct Refund<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub signer: Signer<'info>,

    pub trader: SystemAccount<'info>,

    #[account(
        mut,
        seeds = [Season::SEED, trader.key().as_ref(), season_id.to_le_bytes().as_ref()],
        bump
    )]
    pub season: Account<'info, Season>,

    #[account(
        mut,
        seeds = [SeasonEscrow::SEED, trader.key().as_ref(), season_id.to_le_bytes().as_ref()],
        bump
    )]
    pub season_escrow: Account<'info, SeasonEscrow>,

    #[account(
        init,
        payer = signer,
        space = 8 + SubscriptionPass::INIT_SPACE,
        seeds = [SubscriptionPass::SEED, signer.key().as_ref() ,trader.key().as_ref(), season_id.to_le_bytes().as_ref()],
        bump
    )]
    pub subscription_pass: Account<'info, SubscriptionPass>,

    #[account(
        init,
        payer = signer,
        space = 8 + ClaimPass::INIT_SPACE,
        seeds = [ClaimPass::SEED, signer.key().as_ref() ,trader.key().as_ref(), season_id.to_le_bytes().as_ref()],
        bump
    )]
    pub claim_pass: Account<'info, ClaimPass>,
}

// ################# Signal ##################

#[derive(Accounts)]
pub struct EncryptSignal<'info> {
    pub system_program: Program<'info, System>,

    #[account(mut)]
    pub trader: Signer<'info>,

    #[account(
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump
    )]
    pub trader_account: Box<Account<'info, TraderAccount>>,

    #[account(
        mut,
        seeds = [Season::SEED, trader.key().as_ref(), trader_account.current_season.to_le_bytes().as_ref()],
        bump
    )]
    pub season: Account<'info, Season>,

    #[account(
        init,
        payer = trader,
        space = 8 + Signal::INIT_SPACE,
        // has to be on 1 line
        seeds = [Signal::SEED, trader.key().as_ref(), season.id.to_le_bytes().as_ref(), season.episodes.to_le_bytes().as_ref()], bump)]
    pub signal: Account<'info, Signal>,
}

// #################################################
// ################     Arcium       ###############
// #################################################

// ################     Decrypt signal       ###############

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

#[queue_computation_accounts("decrypt_signal", follower)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct DecryptSignal<'info> {
    pub season: Box<Account<'info, Season>>,

    #[account(mut)]
    pub follower: Signer<'info>,

    pub trader: SystemAccount<'info>,

    #[account(
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump
    )]
    pub trader_account: Box<Account<'info, TraderAccount>>,

    #[account(
        seeds = [SubscriptionPass::SEED, follower.key().as_ref() ,trader.key().as_ref(), signal.metadata.season_id.to_le_bytes().as_ref()],
        bump
    )]
    pub subscription_pass: Box<Account<'info, SubscriptionPass>>,

    pub signal: Box<Account<'info, Signal>>,

    #[account(
    init_if_needed,
    payer = follower,
    space = 8 + 1,
    seeds = [b"ArciumSignerAccount"],
    bump,
    address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, ArciumSignerAccount>>,

    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account)
    )]
    /// CHECK: ``mempool_account``, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,

    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account)
    )]
    /// CHECK: ``executing_pool``, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,

    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account)
    )]
    /// CHECK: ``computation_account``, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,

    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_DECRYPT_SIGNAL)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,

    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Box<Account<'info, FeePool>>,

    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Box<Account<'info, ClockAccount>>,

    pub system_program: Program<'info, System>,

    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("decrypt_signal")]
#[derive(Accounts)]
pub struct DecryptSignalCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,

    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_DECRYPT_SIGNAL)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    /// CHECK: ``computation_account``, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,

    #[account(
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,

    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: ``instructions_sysvar``, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub signal: Box<Account<'info, Signal>>,

    pub requester: SystemAccount<'info>,
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
    pub trader: SystemAccount<'info>,

    #[account(
        seeds = [TraderAccount::SEED, trader.key().as_ref()],
        bump
    )]
    pub trader_account: Account<'info, TraderAccount>,

    pub signal: Box<Account<'info, Signal>>,

    #[account(
    init_if_needed,
    payer = payer,
    space = 8 + RevealedSignal::INIT_SPACE,
    seeds = [RevealedSignal::SEED, signal.metadata.author.as_ref(), signal.metadata.season_id.to_le_bytes().as_ref(), signal.metadata.number.to_le_bytes().as_ref()],
    bump,
    )]
    pub revealed_signal: Box<Account<'info, RevealedSignal>>,

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
    pub sign_pda_account: Box<Account<'info, ArciumSignerAccount>>,

    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account)
    )]
    /// CHECK: ``mempool_account``, checked by the arcium program
    pub mempool_account: UncheckedAccount<'info>,

    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account)
    )]
    /// CHECK: ``executing_pool``, checked by the arcium program
    pub executing_pool: UncheckedAccount<'info>,

    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account)
    )]
    /// CHECK: ``computation_account``, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,

    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_REVEAL_SIGNAL)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,

    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Box<Account<'info, FeePool>>,

    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Box<Account<'info, ClockAccount>>,

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
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    /// CHECK: ``computation_account``, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,

    #[account(
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,

    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: ``instructions_sysvar``, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub signal: Box<Account<'info, Signal>>,

    #[account(mut)]
    pub revealed_signal: Box<Account<'info, RevealedSignal>>,

    pub requester: SystemAccount<'info>,
}

// ###################################
// ############# PROGRAM #############
// ###################################

#[arcium_program]
pub mod shingo_program {

    use arcium_client::idl::arcium::types::{
        CallbackAccount, CircuitSource, OffChainCircuitSource,
    };
    use arcium_macros::circuit_hash;

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
    // ########## Signal: encrypt_signal
    // ######### Arcium ############
    // ######### Arcium : decrypt_signal
    // ######### Arcium : reveal_signal
    // --------------------------------------------------------------

    // ########## Trader ###########

    /// # Errors
    /// Cannot error
    /// Called Once by the trader
    pub fn initialize_trader_account(ctx: Context<InitializeTraderAccount>) -> Result<()> {
        let trader_account = &mut ctx.accounts.trader_account;

        trader_account.current_season = 0;
        trader_account.has_active_season = false;

        emit!(NewTrader {
            public_key: ctx.accounts.trader.key()
        });

        Ok(())
    }

    // ########## Season ###########

    /// # Errors
    /// Theoritically may have an arithemic error that cause Overflow Error
    /// Called multiple times by the trader, at start of a new season
    /// Errors if a Checked Arithmetic operation fails
    /// Errors if ``subscription_price`` is inferior to 100 lamports
    /// Errors if the trader has an active season
    /// Errors if the minimum number of episodes is equal to 0
    pub fn initialize_season(
        ctx: Context<InitializeSeason>,
        subscription_price: u64,
        maximum_spots: u64,
        minimum_episode_count: u64,
    ) -> Result<()> {
        // -- guards
        require!(
            !ctx.accounts.trader_account.has_active_season,
            ShingoProgramError::CannotCreateNewSeasonWhileHasActiveSeason
        );

        let one_hundred_lamports = 100u64;
        require!(
            subscription_price > one_hundred_lamports,
            ShingoProgramError::InvalidSubscriptionPrice
        );

        // --- minimum of 1 episode per season
        require!(minimum_episode_count != 0, ShingoProgramError::Nono);

        // --- update the trader account
        let trader_account = &mut ctx.accounts.trader_account;
        let season_number = trader_account
            .current_season
            .checked_add(1)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        trader_account.current_season = season_number;
        trader_account.has_active_season = true;

        // --- initialize the season
        let season = &mut ctx.accounts.season;
        season.subscription_price = subscription_price;
        season.maximum_subscribers = maximum_spots;
        season.minimum_number_of_episodes = minimum_episode_count;
        season.id = season_number;
        season.is_active = true;
        season.episodes = 0;
        season.trader = ctx.accounts.trader.key();

        // --- create the pass
        let shingo_pass = &mut ctx.accounts.shingo_pass;
        shingo_pass.owner = DEVELOPER_ADDRESS;

        // --- the trader is automatically subscribed to themself and get a pass
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
    /// Errors if the developer system account given is not the actual developer of the smart contract
    /// Errors if a Checked Arithmetic operation fails
    /// Errors if a trader subscribes to themself
    /// Errors if the season is not active
    /// Errors if there isn't any more spots for the season ( subscribers == spots )
    pub fn subscribe_to_season(ctx: Context<SubscribeToSeason>) -> Result<()> {
        // --- can't subscribe to yourself
        require!(
            !ctx.accounts.follower.key.eq(ctx.accounts.trader.key),
            ShingoProgramError::Nono
        );
        // --- can only subscribe to an active season
        require!(ctx.accounts.season.is_active, ShingoProgramError::Nono);

        // --- can only subscribe if there less subscribers than spots
        require!(
            ctx.accounts.season.subscribers < ctx.accounts.season.maximum_subscribers,
            ShingoProgramError::SeasonMaximumSubscribersNumberReached
        );

        let developer = &ctx.accounts.developer;

        require!(
            developer.key.eq(&DEVELOPER_ADDRESS),
            ShingoProgramError::Nono
        );

        let price = ctx.accounts.season.subscription_price;

        let tip = price
            .checked_div(100)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                system_program::Transfer {
                    from: ctx.accounts.follower.to_account_info(),
                    to: ctx.accounts.developer.to_account_info(),
                },
            ),
            tip,
        )?;

        // --- put money into the season's escrow
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                system_program::Transfer {
                    from: ctx.accounts.follower.to_account_info(),
                    to: ctx.accounts.season_escrow.to_account_info(),
                },
            ),
            price,
        )?;

        // --- create the subscription pass for the season
        let subscription_pass = &mut ctx.accounts.subscription_pass;
        subscription_pass.owner = ctx.accounts.follower.key();

        // --- increase the season's subscribers
        let season = &mut ctx.accounts.season;

        let new_subscribers_count = season
            .subscribers
            .checked_add(1)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        season.subscribers = new_subscribers_count;

        emit!(NewSubscription {
            followee: ctx.accounts.trader.key(),
            follower: ctx.accounts.follower.key(),
            season: ctx.accounts.season.id
        });

        Ok(())
    }

    /// # Errors
    /// Called multiple times by the trader, at the end a season
    /// Ending a season makes all its signals decryptable by everyone
    /// Erros if a checked arithmetic operation fails
    /// Errors if the signer isn't the trader of the given season
    /// Errors if the trader does not have an active season
    /// Errors if the season to be closed isn't the current season
    /// Errors if the minimum number of episodes hasn't been reached
    #[allow(clippy::arithmetic_side_effects)]
    pub fn close_season(ctx: Context<CloseSeason>) -> Result<()> {
        // --- guards
        // --- must be the signer and trader of the season to close it
        require!(
            ctx.accounts.season.trader.eq(ctx.accounts.trader.key),
            ShingoProgramError::Sus
        );

        // --- trader's season must be active
        require!(
            ctx.accounts.trader_account.has_active_season,
            ShingoProgramError::CannotCloseSeasonWhileNoActiveSeason
        );

        // --- season to be closed must be the current season
        require!(
            ctx.accounts.season.id == ctx.accounts.trader_account.current_season,
            ShingoProgramError::Nono
        );

        // --- the promised minimum number of episodes must be reached or exceeded
        require!(
            ctx.accounts.season.episodes >= ctx.accounts.season.minimum_number_of_episodes,
            ShingoProgramError::CannotCloseSeasonUntilMinimumNumberOfEpisodesIsReached
        );

        // --- updating the trader account
        let trader_account = &mut ctx.accounts.trader_account;
        trader_account.has_active_season = false;

        // --- updating the season
        let season = &mut ctx.accounts.season;
        season.is_active = false;

        // --- compute the payout
        // --- payout should be upheld by the invariant : subscribers * season's subscription price = payout
        let season = &ctx.accounts.season;
        let all_the_money_from_the_season = season
            .subscribers
            .checked_mul(season.subscription_price)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        // --- pay the trader for their season
        **ctx
            .accounts
            .season_escrow
            .to_account_info()
            .try_borrow_mut_lamports()? -= all_the_money_from_the_season;

        **ctx.accounts.trader.try_borrow_mut_lamports()? += all_the_money_from_the_season;

        emit!(SeasonFinale {
            trader: ctx.accounts.trader.key(),
            season: ctx.accounts.season.id,
            last_episode: ctx.accounts.season.episodes,
        });

        Ok(())
    }

    /// # Errors
    /// Called multiple times by the trader, at the end a season
    /// Ending a season makes all its signals decryptable by everyone
    /// May fail to acquire the Solana's Clock
    /// Errors if a checked arithmetic operation fails
    /// Errors if the trader does not have an active season
    /// Errors if the given season isn't the current season
    /// Errors if the season has reached its minimum number of episodes
    /// Errors if the time elapsed since last seen, is less than 31 days
    pub fn force_close_season(ctx: Context<ForceCloseSeason>, current_season: u64) -> Result<()> {
        // --- guards

        const SECONDS_PER_MINUTE: i64 = 60;
        const MINUTES_PER_HOUR: i64 = 60 * SECONDS_PER_MINUTE;
        const HOURS_PER_DAY: i64 = 24 * MINUTES_PER_HOUR;
        const THIRTY_ONE_DAYS: i64 = 31 * HOURS_PER_DAY;

        let season = &ctx.accounts.season;

        let now = Clock::get()?.unix_timestamp;
        let time_elapsed = now
            .checked_sub(season.last_seen)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        require!(time_elapsed >= THIRTY_ONE_DAYS, ShingoProgramError::Nono);

        require!(
            ctx.accounts.trader_account.current_season == current_season,
            ShingoProgramError::Nono
        );

        // --- the promised minimum number of episodes must not have been reached
        require!(
            season.episodes < season.minimum_number_of_episodes,
            ShingoProgramError::CannotCloseSeasonUntilMinimumNumberOfEpisodesIsReached
        );

        // --- trader's season must be active
        require!(
            ctx.accounts.trader_account.has_active_season,
            ShingoProgramError::CannotCloseSeasonWhileNoActiveSeason
        );

        // --- season to be closed must be the current season
        require!(
            season.id == ctx.accounts.trader_account.current_season,
            ShingoProgramError::Nono
        );

        // --- updating the trader account
        let trader_account = &mut ctx.accounts.trader_account;
        trader_account.has_active_season = false;

        // --- updating the season
        let season = &mut ctx.accounts.season;
        season.is_active = false;

        // --- emit a forcibly closed season
        emit!(ForciblyClosedSeason {
            trader: ctx.accounts.trader.key(),
            season: season.id,
        });

        Ok(())
    }

    /// # Errors
    /// Theoritically may have an arithemic error that cause Overflow
    /// Called multiple times by the followers of a season that has been forcibly closed
    /// Ending a season makes all its signals decryptable by everyone
    #[allow(unused_variables)]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn claim_from_forcibly_closed_season(ctx: Context<Refund>, season_id: u64) -> Result<()> {
        // --- guards
        let season = &ctx.accounts.season;

        // --- season must not be active
        // --- AND
        // --- the promised minimum number of episodes must not have been reached
        let is_forcibly_closed_season =
            !season.is_active && (season.episodes < season.minimum_number_of_episodes);

        require!(is_forcibly_closed_season, ShingoProgramError::Sus);

        let claim_pass = &ctx.accounts.claim_pass;

        require!(!claim_pass.claimed, ShingoProgramError::Sus);

        let subscription_pass = &ctx.accounts.subscription_pass;

        let owner = subscription_pass.owner;

        // --- require that the signer was a subscriber
        require!(
            ctx.accounts.signer.key.eq(&owner),
            ShingoProgramError::NotSubbed
        );

        // --- refund the follower with the subscription_price ( tip isn't refunded )
        **ctx
            .accounts
            .season_escrow
            .to_account_info()
            .try_borrow_mut_lamports()? -= season.subscription_price;

        **ctx.accounts.signer.try_borrow_mut_lamports()? += season.subscription_price;

        // --- invalidate the follower claim's pass to prevent double claims
        let claim_pass = &mut ctx.accounts.claim_pass;
        claim_pass.claimed = true;

        Ok(())
    }

    // ########## Signal ###########

    /// # Errors
    /// Can theoritically error if the ``Clock`` cannot be obtained
    /// Errors if the given season is not active
    /// Errors if a Checked Arithmetic operation fails
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_signal(
        ctx: Context<EncryptSignal>,
        market_left: [u8; 32],
        market_right: [u8; 32],
        side: [u8; 32],
        entry_kind: [u8; 32],
        entry_price: [u8; 32],
        stop_loss: [u8; 32],
        profit_point_price: [u8; 32],
        profit_point_size_percentage: [u8; 32],
        size_usd: [u8; 32],
        leverage: [u8; 32],
        venue: [u8; 32],
        timeframe: [u8; 32],
    ) -> Result<()> {
        // --- can only publish on active seasons
        require!(
            ctx.accounts.season.is_active,
            ShingoProgramError::SeasonIsInactive
        );

        // --- store the encrypted signal
        let signal = &mut ctx.accounts.signal;

        signal.market_left = market_left;
        signal.market_right = market_right;
        signal.side = side;
        signal.entry_kind = entry_kind;
        signal.entry_price = entry_price;
        signal.stop_loss = stop_loss;
        signal.profit_point_price = profit_point_price;
        signal.profit_point_size_percentage = profit_point_size_percentage;
        signal.size_usd = size_usd;
        signal.leverage = leverage;
        signal.venue = venue;
        signal.timeframe = timeframe;
        // --- metadata values
        signal.metadata.number = ctx.accounts.season.episodes;
        signal.metadata.season_id = ctx.accounts.season.id;
        let now = Clock::get()?.unix_timestamp;
        signal.metadata.created_at = now;
        signal.metadata.author = ctx.accounts.trader.key();

        // --- update the season
        let season = &mut ctx.accounts.season;

        let new_count = season
            .episodes
            .checked_add(1)
            .ok_or(ShingoProgramError::CheckedArithmeticFailure)?;

        season.episodes = new_count;
        season.last_seen = now;

        Ok(())
    }

    // ######### Arcium : decrypt_signal ########

    /// # Errors
    /// Cannot error, fn just initializes the ``comp_def``
    /// Called once by the admin
    pub fn init_decrypt_signal_comp_def(ctx: Context<InitDecryptSignalCompDef>) -> Result<()> {
        init_computation_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source:
                    "https://raw.githubusercontent.com/shinsekailabs/shingo_program/main/build/decrypt_signal.arcis"
                        .to_string(),
                hash: circuit_hash!("decrypt_signal"),
            }))
        )?;
        Ok(())
    }

    /// # Errors
    /// Errors if the given season is not active
    /// Errors if the signal does not belong to the given season
    /// Errors if the signer of the transaction is not subbed to signal's season
    /// Errors if a casting operation fails
    /// Errors if ``queue_computation`` fails
    pub fn decrypt_signal(
        ctx: Context<DecryptSignal>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
        sender_pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        // --- guards
        let season = &ctx.accounts.season;
        let signal = &ctx.accounts.signal;
        let trader_account = &ctx.accounts.trader_account;
        // --- can only decrypt signals of active seasons
        require!(season.is_active, ShingoProgramError::SeasonIsInactive);

        // --- signal must belong to the current season
        require!(
            signal.metadata.season_id == trader_account.current_season,
            ShingoProgramError::Nono
        );

        // --- shit must not be sus
        require!(
            signal.metadata.author.eq(ctx.accounts.trader.key),
            ShingoProgramError::Sus
        );

        // --- transaction signer must own the given subscription pass

        let subscription_pass = &ctx.accounts.subscription_pass;

        let owner = subscription_pass.owner;

        require!(
            ctx.accounts.follower.key.eq(&owner),
            ShingoProgramError::NotSubbed
        );
        // --------------------------------------

        let init_space: u32 = Signal::ARCIUM_INIT_SPACE
            .try_into()
            .map_err(|_| ShingoProgramError::CastingFailure)?;

        let offset: u32 = Signal::ARCIUM_OFFSET
            .try_into()
            .map_err(|_| ShingoProgramError::CastingFailure)?;

        let args = ArgBuilder::new()
            .x25519_pubkey(receiver)
            .plaintext_u128(receiver_nonce)
            .x25519_pubkey(sender_pub_key)
            .plaintext_u128(nonce)
            .account(ctx.accounts.signal.key(), offset, init_space)
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![DecryptSignalCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[
                    CallbackAccount {
                        pubkey: ctx.accounts.signal.key(),
                        is_writable: false,
                    },
                    CallbackAccount {
                        pubkey: ctx.accounts.follower.key(),
                        is_writable: false,
                    },
                ],
            )?],
            1,
            0,
        )?;

        Ok(())
    }

    /// # Errors if Arcium's Computation aborted
    #[arcium_callback(encrypted_ix = "decrypt_signal")]
    pub fn decrypt_signal_callback(
        ctx: Context<DecryptSignalCallback>,
        output: SignedComputationOutputs<DecryptSignalOutput>,
    ) -> Result<()> {
        let Ok(DecryptSignalOutput { field_0: my_output }) = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) else {
            emit!(ComputationAborted {
                requester: ctx.accounts.requester.key()
            });
            return Err(ShingoProgramError::AbortedComputation.into());
        };

        let market_left = my_output.ciphertexts[0];

        let market_right = my_output.ciphertexts[1];

        let side = my_output.ciphertexts[2];

        let entry_kind = my_output.ciphertexts[3];

        let entry_price = my_output.ciphertexts[4];

        let stop_loss = my_output.ciphertexts[5];

        let profit_point_price = my_output.ciphertexts[6];

        let profit_point_size_percentage = my_output.ciphertexts[7];

        let size_usd = my_output.ciphertexts[8];

        let leverage = my_output.ciphertexts[9];

        let venue = my_output.ciphertexts[10];

        let timeframe = my_output.ciphertexts[11];

        emit!(ObservableSignal {
            nonce: my_output.nonce.to_le_bytes(),
            metadata: ctx.accounts.signal.metadata.clone(),
            market_left,
            market_right,
            side,
            entry_kind,
            entry_price,
            stop_loss,
            profit_point_price,
            profit_point_size_percentage,
            size_usd,
            leverage,
            venue,
            timeframe,
            requester: ctx.accounts.requester.key(),
        });

        Ok(())
    }

    // ######### Arcium : reveal_signal     ########

    /// # Errors
    /// Cannot fail
    /// Called once by the admin
    pub fn init_reveal_signal_comp_def(ctx: Context<InitRevealSignalCompDef>) -> Result<()> {
        init_computation_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: "https://raw.githubusercontent.com/shinsekailabs/shingo_program/main/build/reveal_signal.arcis"
                    .to_string(),
                hash: circuit_hash!("reveal_signal"),
            }))
        )?;
        Ok(())
    }

    /// # Errors
    /// Errors if the signal's season is active
    /// Errors if the signal's season isn't matching the user given season
    /// Errors if ``queue_computation`` fails
    pub fn reveal_signal(
        ctx: Context<RevealSignal>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
    ) -> Result<()> {
        // --- guards
        let signal = &ctx.accounts.signal;
        let trader_account = &ctx.accounts.trader_account;

        let is_previous_season = signal.metadata.season_id < trader_account.current_season;
        let is_current_closed_season = signal.metadata.season_id == trader_account.current_season
            && !trader_account.has_active_season;

        // --- signal's season_id must be a previous season OR signal's season is the trader's current season that has closed.
        require!(
            is_previous_season || is_current_closed_season,
            ShingoProgramError::Nono
        );

        // --- signal to be revealed must authored by the given trader
        require!(
            signal.metadata.author.eq(ctx.accounts.trader.key),
            ShingoProgramError::Sus
        );

        // --------------------------------------
        let init_space: u32 = Signal::ARCIUM_INIT_SPACE
            .try_into()
            .map_err(|_| ShingoProgramError::CastingFailure)?;

        let offset: u32 = Signal::ARCIUM_OFFSET
            .try_into()
            .map_err(|_| ShingoProgramError::CastingFailure)?;

        let args = ArgBuilder::new()
            .x25519_pubkey(receiver)
            .plaintext_u128(receiver_nonce)
            .account(ctx.accounts.signal.key(), offset, init_space)
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![RevealSignalCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[
                    CallbackAccount {
                        pubkey: ctx.accounts.signal.key(),
                        is_writable: false,
                    },
                    CallbackAccount {
                        pubkey: ctx.accounts.revealed_signal.key(),
                        is_writable: true,
                    },
                    CallbackAccount {
                        pubkey: ctx.accounts.payer.key(),
                        is_writable: true,
                    },
                ],
            )?],
            1,
            0,
        )?;

        Ok(())
    }

    /// # Errors
    /// Errors if the computation aborted
    #[arcium_callback(encrypted_ix = "reveal_signal")]
    pub fn reveal_signal_callback(
        ctx: Context<RevealSignalCallback>,
        output: SignedComputationOutputs<RevealSignalOutput>,
    ) -> Result<()> {
        let Ok(RevealSignalOutput { field_0: my_output }) = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) else {
            emit!(ComputationAborted {
                requester: ctx.accounts.requester.key()
            });
            return Err(ShingoProgramError::AbortedComputation.into());
        };

        let market_left = my_output.field_0;
        let market_right = my_output.field_1;
        let side = my_output.field_2;
        let entry_kind = my_output.field_3;
        let entry_price = my_output.field_4;
        let stop_loss = my_output.field_5;
        let profit_point_price = my_output.field_6;
        let profit_point_size_percentage = my_output.field_7;
        let size_usd = my_output.field_8;
        let leverage = my_output.field_9;
        let venue = my_output.field_10;
        let timeframe = my_output.field_11;

        let revealed_signal = &mut ctx.accounts.revealed_signal;

        revealed_signal.metadata = ctx.accounts.signal.metadata.clone();
        revealed_signal.market_left = market_left;
        revealed_signal.market_right = market_right;
        revealed_signal.side = side;
        revealed_signal.entry_kind = entry_kind;
        revealed_signal.entry_price = entry_price;
        revealed_signal.stop_loss = stop_loss;
        revealed_signal.profit_point_price = profit_point_price;
        revealed_signal.profit_point_size_percentage = profit_point_size_percentage;
        revealed_signal.size_usd = size_usd;
        revealed_signal.leverage = leverage;
        revealed_signal.venue = venue;
        revealed_signal.timeframe = timeframe;

        emit!(ClearSignal {
            metadata: ctx.accounts.signal.metadata.clone(),
            market_left: market_left,
            market_right: market_right,
            side: side,
            entry_kind: entry_kind,
            entry_price: entry_price,
            stop_loss: stop_loss,
            profit_point_price: profit_point_price,
            profit_point_size_percentage: profit_point_size_percentage,
            size_usd: size_usd,
            leverage: leverage,
            venue: venue,
            timeframe: timeframe,
            requester: ctx.accounts.requester.key()
        });

        Ok(())
    }
}
