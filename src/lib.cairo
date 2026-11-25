//use openzeppelin_account::utils::signature;
use starknet::{ContractAddress, get_caller_address, get_contract_address, get_block_timestamp};
pub mod mock;
use starknet::account::Call as StarknetCall;

#[derive(Copy, Drop, Serde)]
    pub struct OutsideExecution {
        pub caller: ContractAddress, // who is allowed to send a transaction
        pub nonce: felt252, // safe from reentracy
        pub execute_after: u64,
        pub execute_before: u64,
        pub calls: Span<StarknetCall>
    }

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
        pub is_configured: bool,
        pub max_per_call: u256,  // max amount per a call
        pub max_per_transaction: u256, // max amount of all transfers of this token in batch
        pub max_per_window: u256, 
        pub window_seconds: u64,
        pub window_start: u64,
        pub spent_in_window: u256
    }

#[derive(Drop, Serde)]
    pub struct Call{
        pub to: ContractAddress, // to token, for example dai
        pub selector: felt252, // what selector, for exemple - transfer
        pub calldata: Span<felt252> // arguments for selector fn 
    }

    // interfaces
#[starknet::interface]
    pub trait IOutsideExecutionV2<TState>{
        fn execute_from_outside_v2(ref self: TState, outside_execution: OutsideExecution, 
            signature: Span<felt252>) -> Array<Span<felt252>>;
        fn is_valid_outside_execution_nonce(self: @TState, nonce: felt252) -> bool;
    }

#[starknet::interface]
    pub trait ISRC5<TState> {
        fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    }

#[starknet::interface]
    pub trait IAccount<TState> {
        fn __validate__(ref self: TState, calls: Array<Call>) -> felt252;
        fn __execute__(ref self: TState, calls: Array<Call>) -> Array<Span<felt252>>;
        fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    }

#[starknet::interface]
    pub trait IDeployable<TState>{
        fn __validate_deploy__(self: @TState, class_hash: felt252, contract_address_salt: felt252,
             pub_keys: Array<felt252>, threshold: u32) -> felt252;
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
       fn get_threshold(self: @TState) -> u32;
       fn get_public_keys(self: @TState, key: felt252) -> bool;
       fn get_public_keys_arr(self: @TState) -> Array<felt252>;
       
       fn set_spending_policy(ref self: TState, session_key: felt252, token: ContractAddress, max_per_call: u256, max_per_transaction: u256, 
       max_per_window: u256, window_seconds: u64);
       fn get_spending_policy(self: @TState, session_key: felt252, token: ContractAddress) -> SpendingPolicy;
       fn get_policy_tokens(self: @TState, session_key: felt252) -> Array<ContractAddress>;
       fn remove_spending_policy(ref self: TState, session_key: felt252, token: ContractAddress);
    }

#[starknet::contract(account)]
pub mod AA {
    use starknet::get_tx_info;
    use starknet::event::EventEmitter;
    use starknet::SyscallResultTrait;
   // use starknet::syscalls::call_contract_syscall;
    use starknet::storage::{Map, StoragePathEntry, StoragePointerReadAccess,
    StoragePointerWriteAccess, Vec, MutableVecTrait, VecTrait};
    use super::{ContractAddress, get_caller_address, get_contract_address, get_block_timestamp,
    SessionKey, SessionEntrypoint, SpendingPolicy, OutsideExecution, StarknetCall};
    use core::ecdsa::check_ecdsa_signature;
    use super::Call;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;

    const SRC5_INTERFACE_ID: felt252 = 0x3f918d17e5ee77373b56385708f855659a07f75997f365cf87748628532a055;
    const SRC6_INTERFACE_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;
    const SNIP9_V2_INTERFACE_ID: felt252 = 0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872;
    const ANY_CALLER: felt252 = 0x414e595f43414c4c4552;
    const CALL_TYPE_HASH: felt252 = 0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9;
    const OUTSIDE_EXECUTION_TYPE_HASH: felt252 = 0x312b56c05a7965066ddbda31c016d8d05afc305071c0ca3cdc2192c3c2f1f0f;
    const STARKNET_DOMAIN_TYPE_HASH: felt252 = 0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210;

    const DEPLOY_ACCOUNT_V3: felt252 = 3;
    const QUERY_VERSION_OFFSET: felt252 = 0x100000000000000000000000000000000;

    #[starknet::storage_node]
    pub struct PolicyTokenRegistry {
        tokens: Vec<ContractAddress>,
    }

    #[storage]
    struct Storage {
       pub public_keys: Map<felt252, bool>,
       pub pub_keys_vec: Vec<felt252>,
       pub threshold: u32,
       pub guardians: Map<ContractAddress, bool>,
       pub session_keys: Map<felt252, SessionKey>,
       pub session_entrypoints: Map<(felt252, u32), SessionEntrypoint>,
       pub spending_policies: Map<(felt252, ContractAddress), SpendingPolicy>,
       pub policy_tokens: Map<felt252, PolicyTokenRegistry>,
       pub outside_nonces: Map<felt252, bool>
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
            assert!(pub_key != 0, "Public key cannot be zero");
            assert!(!self.public_keys.entry(pub_key).read(), "this pub key already added");
            self.public_keys.entry(pub_key).write(true);
            self.pub_keys_vec.push(pub_key);
        }
        self.threshold.write(threshold);
    }

    // helper for signature
    fn count_valid_signatures(self: @ContractState, hash: felt252, signature: Span<felt252>) -> u32 {
        assert!(signature.len() % 3 == 0, "signature len must be a multiple of 3");
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

            // Verify if the extracted pub_key is a registered owner
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

            // Validate ECDSA signature and increment counter if valid
            let is_valid = core::ecdsa::check_ecdsa_signature(hash, pub_key, sig_r, sig_s);
            if is_valid {
                seen.append(pub_key);
                valid_count += 1;
            }
        }

        return valid_count;
    }

    // fn for spending_policies
    fn extract_spending_amount(call: @Call) -> u256 {
        let selector = *call.selector;
    
        let amount_index = if selector == selector!("transfer") {
            1
        } else { assert!(selector == selector!("transfer_from"), "Unsupported spending selector" );
            2
        };
    
        let calldata = call.calldata;
    
        assert!(calldata.len() > amount_index + 1, "Spending: calldata too short");
    
        let amount_low: u128 = match (*calldata.at(amount_index)).try_into() {
            Option::Some(value) => value,
            Option::None => {
                panic!("Spending: invalid amount");
                 0
            }
        };
    
        let amount_high: u128 = match (*calldata.at(amount_index + 1)).try_into() {
            Option::Some(value) => value,
            Option::None => {
                panic!("Spending: invalid amount");
                0
            }
        };
    
        u256 {
            low: amount_low,
            high: amount_high
        }
    }

    fn check_and_update_spending(ref self: ContractState, session_key: felt252, calls: Span<Call>) {
        let now = get_block_timestamp();
    
        let mut i: u32 = 0;
    
        while i < calls.len() {
            let call = calls.at(i);
    
            let token = *call.to;
            let selector = *call.selector;
    
            let is_transfer = selector == selector!("transfer")||selector == selector!("transfer_from");
    
            let is_approval = selector == selector!("approve")||selector == selector!("increase_allowance");
    
            if is_approval {
                let policy = self.spending_policies.entry((session_key, token)).read();
    
                assert!(!policy.is_configured, "Spending: allowance operations disabled");
            }
    
            if is_transfer {
                let mut policy = self.spending_policies.entry((session_key, token)).read();
    
                if policy.is_configured {
                    let mut already_processed = false;
                    let mut previous_index: u32 = 0;
    
                    while previous_index < i {
                        let previous_call = calls.at(previous_index);
                        let previous_selector = *previous_call.selector;
    
                        let previous_is_transfer = previous_selector == selector!("transfer") ||
                            previous_selector == selector!("transfer_from");
    
                        if *previous_call.to == token && previous_is_transfer {
                            already_processed = true;
                            break;
                        }
                        previous_index += 1;
                    }
    
                    if !already_processed {
                        let mut transaction_total: u256 = 0;
                        let mut j: u32 = 0;
    
                        while j < calls.len() {
                            let current_call = calls.at(j);
                            let current_selector = *current_call.selector;
    
                            let current_is_transfer = current_selector == selector!("transfer") ||
                                current_selector == selector!("transfer_from");
    
                            if (*current_call.to == token && current_is_transfer) {
                                if current_selector == selector!("transfer_from") {
                                let felt_aa_address: felt252 = get_contract_address().into();
                                assert!(current_call.calldata.len() >= 4, "Spending: transfer_from calldata too short");
                                    assert!(*current_call.calldata.at(0) == felt_aa_address, "from must be self address in transfer from");
                                }
                                let amount = extract_spending_amount(current_call);
                                assert!(amount <= policy.max_per_call, "Spending: exceeds per-call limit");
                                assert!(amount <= policy.max_per_transaction - transaction_total, "Spending: exceeds transaction limit");
                                transaction_total += amount;
                            }
                            j += 1;
                        }
    
                        if now >= policy.window_start && now - policy.window_start >= policy.window_seconds {
                            policy.spent_in_window = 0;
                            policy.window_start = now;
                        }
    
                        assert!(policy.spent_in_window <= policy.max_per_window, "Spending: invalid window state");
    
                        assert!(transaction_total <= policy.max_per_window - policy.spent_in_window, "Spending: exceeds window limit");
    
                        policy.spent_in_window += transaction_total;
    
                        self.spending_policies.entry((session_key, token)).write(policy);
                    }
                }
            }
    
            i += 1;
        }
    }

    // helpers for spending_policies
    fn register_policy_token(ref self: ContractState, session_key: felt252, token: ContractAddress) {
        let mut registry = self.policy_tokens.entry(session_key);

        let len = registry.tokens.len();
        let mut i: u64 = 0;

        while i < len {
            if registry.tokens.at(i).read() == token {
                return;
            }
            i += 1;
        }

        registry.tokens.push(token);
    }

    fn unregister_policy_token(ref self: ContractState, session_key: felt252, token: ContractAddress) {
        let mut registry = self.policy_tokens.entry(session_key);

        let len = registry.tokens.len();
        let mut i: u64 = 0;

        while i < len {
            if registry.tokens.at(i).read() == token {
                let last_index = len - 1;

                if i != last_index {
                    let last_token = registry.tokens.at(last_index).read();
                    registry.tokens.at(i).write(last_token);
                }

                let _removed = registry.tokens.pop();
                return;
            }
            i += 1;
        }
    }

    fn clear_spending_policies(ref self: ContractState, session_key: felt252) {
        let mut registry = self.policy_tokens.entry(session_key);

        while registry.tokens.len() > 0 {
            let last_index = registry.tokens.len() - 1;
            let token = registry.tokens.at(last_index).read();

            let empty_policy = SpendingPolicy {
                is_configured: false,
                max_per_call: 0,
                max_per_transaction: 0,
                max_per_window: 0,
                window_seconds: 0,
                window_start: 0,
                spent_in_window: 0
            };

            self.spending_policies.entry((session_key, token)).write(empty_policy);
            let _removed = registry.tokens.pop();
        }
    }

    // helpers for checking nonce and setting
    pub fn is_nonce_available(self: @ContractState, nonce: felt252) -> bool{
        !self.outside_nonces.entry(nonce).read()
    }

    fn consume_nonce(ref self: ContractState, nonce: felt252){
        assert!(!self.outside_nonces.entry(nonce).read(), "Nonce already used");
        self.outside_nonces.entry(nonce).write(true);
    }

    // helper for checking OutsideExecution
    fn assert_outside_execution_preconditions(self: @ContractState, outside_execution: OutsideExecution){
        let any_caller: ContractAddress = ANY_CALLER.try_into().unwrap();
        let now = get_block_timestamp();
        assert!(get_caller_address() == outside_execution.caller || outside_execution.caller == any_caller, "Invalid calling");
        assert!(outside_execution.execute_after < now, "not yet valid");
        assert!(now < outside_execution.execute_before, "expired");
        assert!(is_nonce_available(self, outside_execution.nonce), "nonce already used");
    }

    // hashing fn helpers
    fn hash_outside_call(call: @StarknetCall) -> felt252{
        let calldata: Span<felt252> = *call.calldata;
        let calldata_hash = poseidon_hash_span(calldata);
        let to: felt252 = (*call.to).into();
        let selector = *call.selector;
        let call_hash: felt252 = poseidon_hash_span(array![CALL_TYPE_HASH, to, selector, calldata_hash].span());
        return call_hash;
    }

    pub fn hash_outside_calls(calls: Span<StarknetCall>) -> felt252{
        let mut arr: Array<felt252> = ArrayTrait::new();
        for call in calls{
            arr.append(hash_outside_call(call));
        }
        let hash_res = poseidon_hash_span(arr.span());
        return hash_res;
    }

    // hashing for SNIP-9
    pub fn hash_outside_execution_struct(outside_execution: @OutsideExecution) -> felt252{
        let felt_caller: felt252 = (*outside_execution.caller).into();
        let nonce = *outside_execution.nonce;
        let execution_after: felt252 = (*outside_execution.execute_after).into();
        let execution_before: felt252 = (*outside_execution.execute_before).into();
        let calls_hash = hash_outside_calls(*outside_execution.calls);
        return poseidon_hash_span(array![OUTSIDE_EXECUTION_TYPE_HASH, felt_caller, nonce, execution_after, execution_before, calls_hash].span());
    }

    pub fn hash_outside_execution_domain(chain_id: felt252) -> felt252{
        let (name, version, revision) = ('Account.execute_from_outside', 2, 1);
        return poseidon_hash_span(array![STARKNET_DOMAIN_TYPE_HASH, name, version, chain_id, revision].span());
    }

    pub fn hash_outside_execution_message(account_address: ContractAddress, outside_execution: @OutsideExecution, chain_id: felt252) -> felt252{
        let domain_hash = hash_outside_execution_domain(chain_id);
        let felt_address: felt252 = account_address.into();
        let struct_hash = hash_outside_execution_struct(outside_execution);
        return poseidon_hash_span(array!['StarkNet Message', domain_hash, felt_address, struct_hash].span());
    }
    
    #[abi(embed_v0)]
    impl Account of super::IAccount<ContractState>{
    
        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            assert!(starknet::get_caller_address() == Zero::zero(), "Only protocol call allowed");
            assert!(calls.len() > 0, "Empty calls array");
            let tx_info = starknet::get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;

            let valid_count = count_valid_signatures(@self, tx_hash, signature);

            // multisig
            if(valid_count >= self.threshold.read()){
                return starknet::VALIDATED;
            }
            
            assert!(signature.len() == 3, "Invalid signature length");

            //session_key
            let key_felt = *signature.at(0);
            assert!(!self.public_keys.entry(key_felt).read(), "owner key can't be used as session key");
            let r = *signature.at(1);
            let s = *signature.at(2);
            let mut session_key: SessionKey = self.session_keys.entry(key_felt).read();

            assert!(session_key.expires_at > get_block_timestamp(), "Session key expired");
            assert!(session_key.max_calls > session_key.calls_used, "max_calls expired");

            let this_contract = get_contract_address();            
            let len = session_key.allowed_entrypoints_len;
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
            assert!(starknet::get_caller_address() == Zero::zero(), "Only protocol call allowed");
            let tx_info = starknet::get_tx_info().unbox();
            let version = tx_info.version;
            assert!(version != 0, "Unsupported transaction version");
            let signature = tx_info.signature;
                if(signature.len() == 3){
                    let key_felt = *signature.at(0);
                    let is_owner = self.public_keys.entry(key_felt).read();
                    if(!is_owner) {
                        check_and_update_spending(ref self, key_felt, calls.span());
                    }
                }
            let mut results: Array<Span<felt252>> = ArrayTrait::new();
            
           for call in calls{
                let res = starknet::syscalls::call_contract_syscall(
                     call.to,
                     call.selector, 
                     call.calldata).unwrap_syscall();
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
    impl Deployable of super::IDeployable<ContractState>{
        fn __validate_deploy__(self: @ContractState, class_hash: felt252, contract_address_salt: felt252, pub_keys: Array<felt252>, threshold: u32) -> felt252{
            let tx_info = get_tx_info().unbox();
           assert!(get_caller_address() == Zero::zero(), "Only protocol call allowed");
           assert!(tx_info.version == DEPLOY_ACCOUNT_V3 ||
           tx_info.version == DEPLOY_ACCOUNT_V3 + QUERY_VERSION_OFFSET, "DeployAccount: unsupported transaction version");
           let tx_hash = tx_info.transaction_hash;
           let signature = tx_info.signature;
           let valid_count = count_valid_signatures(self, tx_hash, signature);
           assert!(valid_count >= self.threshold.read(), "DeployAccount: invalid signature");
           return starknet::VALIDATED;
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
            assert!(get_block_timestamp() < expires_at, "expires_at must be bigger than actual block timestemp");
            assert!(expires_at % 3600 == 0, "expires_at must be a multiple of 3600");
            assert!(max_calls > 0, "max_calls must be greater than zero");
            assert!(allowed_entrypoints.len() > 0, "allowed_entrypoints must not be empty");
            assert!(!self.public_keys.entry(key).read() , "owner can't get session keys");
            
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

            // here we are nullifying spending_policies
            clear_spending_policies(ref self, key);
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
            assert!(new_pub_key != 0, "New public key cannot be 0");
            assert!(self.public_keys.entry(old_pub_key).read(), "old owner is not on owners");
            assert!(!self.public_keys.entry(new_pub_key).read(), "new_owner is already on owners");

            let keys_len = self.pub_keys_vec.len();
            let mut found: bool = false;
            let mut i: u64 = 0;
            while  i < keys_len{
                if(self.pub_keys_vec.at(i).read() == old_pub_key){
                    found = true;
                    break;
                }
                i += 1
            }
            assert!(found, "old pub key must be founded");

            clear_spending_policies(ref self, new_pub_key);

            // nullifying session entrypoints
            let entrypoint_len = self.session_keys.entry(new_pub_key).allowed_entrypoints_len.read();
            for i in 0..entrypoint_len {
                let entrypoint_nullifier = SessionEntrypoint {
                    target_contract: Zero::zero(),
                    selector: 0
                };

                self.session_entrypoints.entry((new_pub_key, i)).write(entrypoint_nullifier);
            }

            // nullifying session keys
            let session_key = SessionKey { expires_at: 0, max_calls: 0, calls_used: 0, allowed_entrypoints_len: 0};
            self.session_keys.entry(new_pub_key).write(session_key);

            // replacing owner
            self.pub_keys_vec.at(i).write(new_pub_key);
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

         fn get_threshold(self: @ContractState) -> u32{
            self.threshold.read()
         }

         fn get_public_keys(self: @ContractState, key: felt252) -> bool {
            self.public_keys.entry(key).read()
         }

         fn get_public_keys_arr(self: @ContractState) -> Array<felt252>{
            let mut result: Array<felt252> = ArrayTrait::new();
            let len = self.pub_keys_vec.len();
            
            let mut i: u64 = 0;
            while i < len {

                let val = self.pub_keys_vec.at(i).read();
                result.append(val);
                i += 1;
            };

            result
         }

         fn set_spending_policy(ref self: ContractState, session_key: felt252, token: ContractAddress, 
          max_per_call: u256, max_per_transaction: u256, max_per_window: u256, window_seconds: u64){
            assert!(get_caller_address() == get_contract_address(), "Only self call allowed");
            let session_key_info =  self.session_keys.entry(session_key).read();
            assert!(session_key_info.expires_at > get_block_timestamp(), "Session key expired");
            assert!(session_key_info.max_calls > session_key_info.calls_used, "Session key already used");
            assert!(token != Zero::zero(), "Invalid token address");
            assert!(window_seconds > 0, "window seconds must be greater zero");
            register_policy_token(ref self, session_key, token);
            let new_spending_policy = SpendingPolicy { is_configured: true, max_per_call: max_per_call, max_per_transaction: max_per_transaction,
            max_per_window: max_per_window, window_seconds: window_seconds, window_start: get_block_timestamp(), spent_in_window: 0 };
            self.spending_policies.entry((session_key, token)).write(new_spending_policy);
         }

         fn get_spending_policy(self: @ContractState, session_key: felt252, token: ContractAddress) -> SpendingPolicy{
            self.spending_policies.entry((session_key, token)).read()
         }

         fn get_policy_tokens(self: @ContractState, session_key: felt252) -> Array<ContractAddress>{
            let registry = self.policy_tokens.entry(session_key);
            let len = registry.tokens.len();

            let mut result: Array<ContractAddress> = ArrayTrait::new();
            let mut i: u64 = 0;

            while i < len {
                result.append(registry.tokens.at(i).read());
                i += 1;
            }

            result
         }

         fn remove_spending_policy(ref self: ContractState, session_key: felt252, token: ContractAddress){
           assert!(get_caller_address() == get_contract_address(), "Only self call allowed");
           let new_spending_policy = SpendingPolicy { is_configured: false, max_per_call: 0, max_per_transaction: 0,
           max_per_window: 0, window_seconds: 0, window_start: 0, spent_in_window: 0 };
           self.spending_policies.entry((session_key, token)).write(new_spending_policy);
           unregister_policy_token(ref self, session_key, token);
         }
         
    }

    #[abi(embed_v0)]
    impl SRC5Impl of super::ISRC5<ContractState>{
        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool{
            interface_id == SRC5_INTERFACE_ID || interface_id == SRC6_INTERFACE_ID || interface_id == SNIP9_V2_INTERFACE_ID
        }
    }

    #[abi(embed_v0)]
    impl OutsideExecutionV2 of super::IOutsideExecutionV2<ContractState>{
        fn is_valid_outside_execution_nonce(self: @ContractState, nonce: felt252) -> bool{
            is_nonce_available(self, nonce)
        }

        fn execute_from_outside_v2(ref self: ContractState, outside_execution: OutsideExecution,  signature: Span<felt252>) -> Array<Span<felt252>>{
            let tx_info = get_tx_info().unbox();
            assert_outside_execution_preconditions(@self, outside_execution);
            let message_hash = hash_outside_execution_message(get_contract_address(), @outside_execution, tx_info.chain_id);
            let valid_count = count_valid_signatures(@self, message_hash, signature);
            assert!(valid_count >= self.threshold.read(), "OutsideExecution: invalid signature");
            consume_nonce(ref self, outside_execution.nonce);
            let mut arr: Array<Span<felt252>> = ArrayTrait::new();
            for call in outside_execution.calls{
                let res = starknet::syscalls::call_contract_syscall(*call.to, *call.selector, *call.calldata).unwrap_syscall();
                arr.append(res);
            }
            return arr;
        }


    }

}
