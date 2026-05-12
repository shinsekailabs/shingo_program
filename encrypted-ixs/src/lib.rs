use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

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

    pub struct Signal {
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
    }

    #[instruction]
    pub fn decrypt_signal(
        receiver: Shared,
        input_ctxt: Enc<Shared, Signal>,
    ) -> Enc<Shared, Signal> {
        let input = input_ctxt.to_arcis();
        receiver.from_arcis(input)
    }
    #[instruction]
    pub fn reveal_signal(encrypted_signal: Enc<Shared, Signal>) -> Signal {
        let arcis_signal = encrypted_signal.to_arcis();
        arcis_signal.reveal()
    }
}
