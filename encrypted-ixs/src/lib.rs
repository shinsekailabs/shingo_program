use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

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

    pub struct Signal {
        pub market_left: Ticker,
        pub market_right: Ticker,
        /// LONG = 0 | SHORT = 1
        pub side: u64,
        pub entry_kind: u64,
        pub entry_price: u64,
        pub stop_loss: u64,
        pub profit_point_price: u64,
        pub profit_point_size_pourcentage: u64,
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
