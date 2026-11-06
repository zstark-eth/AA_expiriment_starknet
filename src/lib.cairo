use starknet::{ContractAddress, get_caller_address, get_contract_address, get_block_timestamp};

#[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct SessionKey{
        pub expires_at: u64,
        pub max_calls: u32,
        pub calls_used: u32,
        pub allowed_entrypoints_len: u32
    }

#[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct SessionEntrypoint{
       pub target_contract: ContractAddress, // contract that we call, for example - USDC
       pub selector: felt252, // selector of contract that we call, for example - transfer
    }

#[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct SpendingPolicy{
        is_configured: bool,
        max_per_call: u256,  // max amount per a call
        max_per_transaction: u256, // max amount of all transfers of this token in batch
        max_per_window: u256, // 
        window_seconds: u64,
        window_start: u64,
        spent_in_window: u256
    }

#[derive(Drop, Serde)]
    pub struct Call{
        pub to: ContractAddress,
        pub selector: felt252,
        pub calldata: Array<felt252>
    }

#[starknet::interface]
    pub trait IAccount<TState> {
        fn __validate__(ref self: TState, calls: Array<Call>) -> felt252;
        fn __execute__(ref self: TState, calls: Array<Call>) -> Array<Span<felt252>>;
        fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    }

#[starknet::interface]
    pub trait IAccountManagement<TState> {
       fn add_guardian(ref self: TState, address: ContractAddress);
       fn remove_guardian(ref self: TState, address: ContractAddress);
       fn add_session_key(ref self: TState, key: felt252, expires_at: u64, max_calls: u32, allowed_entrypoints: Array<SessionEntrypoint>);
       fn revoke_session_key(ref self: TState, key: felt252);
       fn replace_owner(ref self: TState, old_pub_key: felt252, new_pub_key: felt252);
       fn get_session_key(self: @TState, key: felt252) -> SessionKey;
       fn get_allowed_entrypoints(self: @TState, key: felt252) -> Array<SessionEntrypoint>;
    }

#[starknet::contract(account)]
pub mod AA {
    use starknet::storage::StorageMapWriteAccess;
use starknet::event::EventEmitter;
    use starknet::SyscallResultTrait;
    use starknet::syscalls::call_contract_syscall;
    use starknet::storage::{Map, StoragePathEntry, StoragePointerReadAccess,
    StoragePointerWriteAccess, Vec, MutableVecTrait, VecTrait};
    use super::{ContractAddress, get_caller_address, get_contract_address, get_block_timestamp, SessionKey, SessionEntrypoint, SpendingPolicy};
    use core::ecdsa::check_ecdsa_signature;
    use super::Call;
    use super::IAccountManagement;
    use core::num::traits::Zero;

    #[storage]
    struct Storage {
        public_keys: Map<felt252, bool>,
        threshold: u32,
        guardians: Map<ContractAddress, bool>,
       pub session_keys: Map<felt252, SessionKey>,
       pub session_entrypoints: Map<(felt252, u32), SessionEntrypoint>,
       spending_policies: Map<(felt252, ContractAddress), SpendingPolicy>

    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event{
        OwnerAdded: OwnerAdded,
        OwnerRemoved: OwnerRemoved,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnerAdded{
        pub_key: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnerRemoved {
        pub_key: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, pub_keys: Array<felt252>, threshold: u32){

        
        assert!(pub_keys.len() >= threshold && threshold > 0, "Invalid threshold or public keys length");
        for pub_key in pub_keys {
            self.public_keys.entry(pub_key).write(true);
        }
        self.threshold.write(threshold);
    }

    fn count_valid_signatures(self: @ContractState, hash: felt252, signature: Span<felt252>) -> u32 {
        let mut valid_count = 0;
        let mut i = 0;

        // Track already verified owners to prevent duplicate signature exploits
        let mut seen: Array<felt252> = ArrayTrait::new();

        while (i + 3 <= signature.len()) {
            let pub_key = *signature[i];
            let sig_r = *signature[i + 1];
            let sig_s = *signature[i + 2];

            // Increment index early to prevent infinite loops on skipped iterations
            i += 3;

            // Verify if the extracted address is a registered owner
            if !self.public_keys.entry(pub_key).read() {
                continue;
            }

            // Check if this owner has already submitted a signature in this call
            let mut already_seen = false;
            let mut j: u32 = 0;
            while j < seen.len() {
                if *seen.at(j) == pub_key {
                    already_seen = true;
                    break;
                }
                j += 1;
            };

            if already_seen {
                continue;
            }

            seen.append(pub_key);
            // Validate ECDSA signature and increment counter if valid
            let is_valid = core::ecdsa::check_ecdsa_signature(hash, pub_key, sig_r, sig_s);
            if is_valid {
                valid_count += 1;
            }
        }

        return valid_count;
    }

    #[abi(embed_v0)]
    impl Account of super::IAccount<ContractState>{

        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;

            let valid_count = count_valid_signatures(@self, tx_hash, signature);

            // multisig
            if(valid_count >= self.threshold.read()){
                return starknet::VALIDATED;
            }

            assert!(signature.len() >= 3, "Invalid signature length");

            //session_key
            let key_felt = *signature.at(0);
            let r = *signature.at(1);
            let s = *signature.at(2);
            let mut session_key: SessionKey = self.session_keys.entry(key_felt).read();

            assert!(session_key.expires_at > get_block_timestamp(), "Session key expired");
            assert!(session_key.max_calls > session_key.calls_used, "max_calls expired");

            let this_contract = get_contract_address();            
            let len =  session_key.allowed_entrypoints_len;
            for call in calls.span() {
                let mut is_allowed = false;
                let mut i = 0;
                assert!(*call.to != this_contract, "session keys can't manage itself");

                while(i < len) {
                    if(self.session_entrypoints.entry((key_felt, i)).selector.read() == *call.selector &&
                    self.session_entrypoints.entry((key_felt, i)).target_contract.read() == *call.to) {
                        is_allowed = true;
                        break;
                    }else{
                        i += 1;
                    }
                }
                assert!(is_allowed == true, "entrypoint isn't allowed");
            }
 
            
            let is_valid_crypto = check_ecdsa_signature(tx_hash, key_felt, r, s);
            assert!(is_valid_crypto, "Invalid session key signature");

            session_key.calls_used += 1;
            self.session_keys.entry(key_felt).write(session_key);

            return starknet::VALIDATED;

        }

        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            let zero_address: ContractAddress = Zero::zero();
            assert!(starknet::get_caller_address() == zero_address, "Only self call allowed");
            let mut results: Array<Span<felt252>> = ArrayTrait::new();
           for call in calls{
                
                let res = starknet::syscalls::call_contract_syscall(
                     call.to,
                     call.selector, 
                     call.calldata.span()).unwrap_syscall();
            results.append(res);
           }
            return results;
        }

        fn is_valid_signature(self: @ContractState, hash: felt252, signature: Array<felt252>) -> felt252 {
            let sig_span: Span<felt252> = signature.span();
            let valid_count = count_valid_signatures(self, hash, sig_span);
            if(valid_count >= self.threshold.read()){
                return starknet::VALIDATED;
            }
            0
        }
    }

    #[abi(embed_v0)]
    impl AccountManagement of super::IAccountManagement<ContractState>{

        fn add_guardian(ref self: ContractState, address: ContractAddress){
            assert!(get_caller_address() == get_contract_address(), "Only self call allowed");
            self.guardians.entry(address).write(true);
        }

        fn remove_guardian(ref self: ContractState, address: ContractAddress){
            assert!(get_caller_address() == get_contract_address(), "Only self call allowed");
            self.guardians.entry(address).write(false);
        }

        fn add_session_key(ref self: ContractState, key: felt252, expires_at: u64, max_calls: u32, allowed_entrypoints: Array<SessionEntrypoint>){
            assert!(get_caller_address() == get_contract_address(), "Only self call allowed");
            let new_entrypoints_len = allowed_entrypoints.len();
            let old_entrypoints_len = self.session_keys.entry(key).allowed_entrypoints_len.read();
            let mut i = 0;

         if(new_entrypoints_len < old_entrypoints_len){
             
             for j in new_entrypoints_len..old_entrypoints_len{
                let entrypoint_nullifier = SessionEntrypoint { target_contract: Zero::zero(), selector: 0};
                self.session_entrypoints.entry((key, j)).write(entrypoint_nullifier);
            }
         }
            for entrypoint in allowed_entrypoints{
                let session_entrypoints = SessionEntrypoint { target_contract: entrypoint.target_contract, selector:  entrypoint.selector};
                self.session_entrypoints.entry((key, i)).write(session_entrypoints);
                i += 1;
            }

            let session_key = SessionKey {expires_at: expires_at, max_calls: max_calls, calls_used: 0, allowed_entrypoints_len: new_entrypoints_len};
            self.session_keys.entry(key).write(session_key);
        }

        fn revoke_session_key(ref self: ContractState, key: felt252){
            assert!(get_caller_address() == get_contract_address(), "Only self call allowed");
            let entrypoint_len = self.session_keys.entry(key).allowed_entrypoints_len.read();
            for i in 0..entrypoint_len{
                let entrypoint_nullifier = SessionEntrypoint { target_contract: Zero::zero(), selector: 0 };
                self.session_entrypoints.entry((key, i)).write(entrypoint_nullifier);
            }
            let session_key = SessionKey { expires_at: 0, max_calls: 0, calls_used: 0, allowed_entrypoints_len: 0};
            self.session_keys.entry(key).write(session_key);
        }

        fn replace_owner(ref self: ContractState, old_pub_key: felt252, new_pub_key: felt252){
            assert!(self.guardians.entry(get_caller_address()).read(), "Only guardians can call this fn");
            assert!(self.public_keys.entry(old_pub_key).read(), "old owner is not on owners");
            assert!(!self.public_keys.entry(new_pub_key).read(), "new_owner is already on owners");
            assert!(new_pub_key != 0, "New public key cannot be 0");
            self.public_keys.entry(old_pub_key).write(false);
            self.public_keys.entry(new_pub_key).write(true);
            self.emit(OwnerRemoved { pub_key: old_pub_key });
            self.emit(OwnerAdded{pub_key: new_pub_key});
        }

        fn get_session_key(self: @ContractState, key: felt252) -> SessionKey{
             self.session_keys.entry(key).read() 
        }

        fn get_allowed_entrypoints(self: @ContractState, key: felt252) -> Array<SessionEntrypoint> {
            let mut my_array = ArrayTrait::new();
            let len = self.session_keys.entry(key).allowed_entrypoints_len.read();
            let mut i = 0;
            while i < len {
            my_array.append(self.session_entrypoints.entry((key, i)).read());
                i += 1;
            };
            return my_array;
         }




    }

    
}
