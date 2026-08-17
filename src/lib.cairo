use starknet::{ContractAddress, get_caller_address, get_contract_address, get_block_timestamp};

#[derive(Drop, Serde, Copy, starknet::Store)]
    struct SessionKey{
        allowed_contract: ContractAddress,
        expires_at: u64,
        max_amount: u256,
    }

#[derive(Drop, Serde)]
    struct Call{
        to: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>
    }

#[starknet::interface]
    trait IAccount<TState> {
        fn __validate__(ref self: TState, calls: Array<Call>) -> felt252;
        fn __execute__(ref self: TState, calls: Array<Call>) -> Array<Span<felt252>>;
        fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    }

#[starknet::interface]
    trait IAccountManagement<TState> {
       fn add_guardian(ref self: TState, address: ContractAddress);
       fn remove_guardian(ref self: TState, address: ContractAddress);
       fn add_session_key(ref self: TState, key: felt252, allowed_contract: ContractAddress, expires_at: u64, max_amount: u256);
       fn revoke_session_key(ref self: TState, key: felt252);
       fn replace_owner(ref self: TState, old_pub_key: felt252, new_pub_key: felt252);
    }

#[starknet::contract(account)]
mod AA {
    use starknet::event::EventEmitter;
    use starknet::SyscallResultTrait;
    use starknet::syscalls::call_contract_syscall;
    use starknet::storage::{Map, StoragePathEntry, StoragePointerReadAccess,
    StoragePointerWriteAccess, Vec,};
    use super::{ContractAddress, get_caller_address, get_contract_address, SessionKey, get_block_timestamp};
    use core::ecdsa;
    use core::ecdsa::check_ecdsa_signature;
    use super::Call;
    use super::IAccountManagement;
    use core::num::traits::Zero;

    #[storage]
    struct Storage {
        public_keys: Map<felt252, bool>,
        threshold: u32,
        guardians: Map<ContractAddress, bool>,
        session_keys: Map<felt252, SessionKey>,
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
    fn constructor(ref self: ContractState, pub_key_0: felt252, pub_key_1: felt252, pub_key_2: felt252){
        self.public_keys.entry(pub_key_0).write(true);
        self.public_keys.entry(pub_key_1).write(true);
        self.public_keys.entry(pub_key_2).write(true);
        self.threshold.write(2);

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
            let session_key: SessionKey = self.session_keys.entry(key_felt).read();

            let zero_address: ContractAddress = Zero::zero();
            assert!(session_key.allowed_contract != zero_address, "Session key does not exist or revoked");
            assert!(session_key.expires_at > get_block_timestamp(), "Session key expired");

            for call in calls.span() {
                assert!(*call.to == session_key.allowed_contract, "Session key: unauthorized contract");
            }

            let is_valid_crypto = check_ecdsa_signature(tx_hash, key_felt, r, s);
            assert!(is_valid_crypto, "Invalid session key signature");
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

        fn add_session_key(ref self: ContractState, key: felt252, allowed_contract: ContractAddress, expires_at: u64, max_amount: u256){
            assert!(get_caller_address() == get_contract_address(), "Only self call allowed");

            let session_key = SessionKey { allowed_contract: allowed_contract, expires_at: expires_at, max_amount:  max_amount};
            self.session_keys.entry(key).write(session_key);
        }

        fn revoke_session_key(ref self: ContractState, key: felt252){
            assert!(get_caller_address() == get_contract_address(), "Only self call allowed");
            let zero_address: ContractAddress = Zero::zero();
            let session_key = SessionKey { allowed_contract: zero_address, expires_at: 0, max_amount: 0};
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




    }

    
}
