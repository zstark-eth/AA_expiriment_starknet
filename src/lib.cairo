use starknet::{ContractAddress, get_caller_address, get_contract_address};

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
    }

#[starknet::contract(account)]
mod AA {
    use starknet::SyscallResultTrait;
    use starknet::syscalls::call_contract_syscall;
    use starknet::storage::{Map, StoragePathEntry, StoragePointerReadAccess,
    StoragePointerWriteAccess, Vec,};
    use super::{ContractAddress, get_caller_address, get_contract_address, SessionKey};
    use starknet::secp256k1::Secp256k1Point;
    use core::ecdsa;
    use super::Call;
    use super::IAccountManagement;
    use core::num::traits::Zero;

    #[storage]
    struct Storage {
        owners: Map<ContractAddress, bool>,
        threshold: u32,
        guardians: Map<ContractAddress, bool>,
        session_keys: Map<felt252, SessionKey>,
        nonce: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event{
        OwnerAdded: OwnerAdded,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnerAdded{
        address: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, address_0: ContractAddress, address_1: ContractAddress, address_2: ContractAddress){
        self.owners.entry(address_0).write(true);
        self.owners.entry(address_1).write(true);
        self.owners.entry(address_2).write(true);
        self.threshold.write(2);

    }

    fn is_valid_signature_for_owner(
        owner: ContractAddress,
        hash: felt252,
        sig_r: felt252,
        sig_s: felt252
     ) -> bool {
        let owner_felt: felt252 = owner.into();
        ecdsa::check_ecdsa_signature(hash, owner_felt, sig_r, sig_s)
    }

    fn count_valid_signatures(self: @ContractState, hash: felt252, signature: Span<felt252>) -> u32 {
        let mut valid_count = 0;
        let mut i = 0;

        // Track already verified owners to prevent duplicate signature exploits
        let mut seen: Array<ContractAddress> = ArrayTrait::new();

        while (i + 3 <= signature.len()) {
            let owner_felt = *signature[i];
            let owner: ContractAddress = owner_felt.try_into().unwrap();
            
            let sig_r = *signature[i + 1];
            let sig_s = *signature[i + 2];

            // Increment index early to prevent infinite loops on skipped iterations
            i += 3;

            // Verify if the extracted address is a registered owner
            if !self.owners.entry(owner).read() {
                continue;
            }

            // Check if this owner has already submitted a signature in this call
            let mut already_seen = false;
            let mut j: u32 = 0;
            while j < seen.len() {
                if *seen.at(j) == owner {
                    already_seen = true;
                    break;
                }
                j += 1;
            };

            if already_seen {
                continue;
            }

            // Validate ECDSA signature and increment counter if valid
            let is_valid = is_valid_signature_for_owner(owner, hash, sig_r, sig_s);
            if is_valid {
                valid_count += 1;
                seen.append(owner);
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
            assert(valid_count >= self.threshold.read(), 'Invalid signature count');
            return starknet::VALIDATED;
        }

        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            assert!(starknet::get_caller_address() == starknet::get_contract_address(), "Only self call allowed");
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


    }

    
}
