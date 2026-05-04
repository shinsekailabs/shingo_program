use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    pub struct ProfitPoint {
        pub price: u64,
        pub size_pourcentage: u64,
    }

    /// Ticker
    ///
    /// SOL = 1  <br>
    /// BTC = 2  <br>
    /// ETH = 3  <br>
    /// USDS (USD Sky / DAI new name) = 4  <br>
    /// USDT = 5  <br>
    /// USDC = 6  <br>
    /// JupUSD = 7  <br>
    /// EURC = 8  <br>
    /// USDG = 9  <br>
    /// PyUSD = 10  <br>
    pub type Ticker = u64;

    pub struct Entry {
        pub kind: u8,
        pub price: u64,
    }

    pub struct Signal {
        pub market_left: Ticker,
        pub market_right: Ticker,
        /// LONG = 0 | SHORT = 1
        pub side: u8,
        pub entry: Entry,
        pub stop_loss: u64,
        pub profit_points: ProfitPoint,
        pub size_usd: u64,
        pub leverage: u64,
        pub venue: u8,
        pub timeframe: u64,
        // -- clear values
        pub season_id: u64,
        pub number: u64,
        pub created_at: i64,
        // pub author: [u8; 32] // Pubkey,
        // pub author: [u128; 2] // Pubkey,
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

    // --- share medical records reproduction ---
    // Code from : https://github.com/arcium-hq/examples/blob/main/share_medical_records/encrypted-ixs/src/lib.rs
    pub struct PatientData {
        pub patient_id: u64,
        pub age: u8,
        pub gender: bool,
        pub blood_type: u8,
        pub weight: u16,
        pub height: u16,
        pub allergies: [bool; 5],
    }

    #[instruction]
    pub fn share_patient_data(
        receiver: Shared,
        input_ctxt: Enc<Shared, PatientData>,
    ) -> Enc<Shared, PatientData> {
        let input = input_ctxt.to_arcis();
        receiver.from_arcis(input)
    }
}
