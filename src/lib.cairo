use starknet::{ContractAddress, get_caller_address,};

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

#[starknet::contract]
mod AA {
    use starknet::storage::{Map, StoragePathEntry, StoragePointerReadAccess,
    StoragePointerWriteAccess, Vec,};
    use super::{ContractAddress, get_caller_address, SessionKey};
    use starknet::secp256k1::Secp256k1Point;
    use core::ecdsa;

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

    

    
}
