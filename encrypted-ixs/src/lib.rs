use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    pub struct ProfitPoint {
        pub price: u64,
        pub size_pourcentage: u64,
    }

    pub struct Market {
        pub left: [u8; 16],
        pub right: [u8; 16],
    }

    pub struct Entry {
        pub kind: u8,
        pub price: u64,
    }

    pub struct Signal {
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
