use aa_experiment::AA::is_nonce_available;
use snforge_std::cheatcodes::execution_info::contract_address;

#[cfg(test)]
mod tests{
    use openzeppelin_account::utils::signature;
    use snforge_std::start_cheat_block_timestamp;
    use super::contract_address;
    use openzeppelin_account::account;
    use snforge_std::start_cheat_signature;
    use starknet::ContractAddress;
    use snforge_std::{start_cheat_transaction_hash,
        ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address, stop_cheat_caller_address, 
        stop_cheat_signature, stop_cheat_transaction_hash, start_cheat_chain_id, stop_cheat_chain_id};
    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
    use core::num::traits::Zero;
    
    use starknet::account::Call as StarknetCall;
    use aa_experiment::AA::{hash_outside_calls, hash_outside_execution_struct, hash_outside_execution_domain, hash_outside_execution_message};
    use aa_experiment::IAccountManagementDispatcher;
    use aa_experiment::IAccountManagementDispatcherTrait;
    use aa_experiment::IAccountDispatcher;
    use aa_experiment::IAccountDispatcherTrait;
    use aa_experiment::IAccountSafeDispatcher;
    use aa_experiment::IAccountSafeDispatcherTrait;
    use aa_experiment::ISRC5Dispatcher;
    use aa_experiment::ISRC5DispatcherTrait;
    use aa_experiment::IOutsideExecutionV2Dispatcher;
    use aa_experiment::IOutsideExecutionV2SafeDispatcher;
    use aa_experiment::IOutsideExecutionV2SafeDispatcherTrait;
    use aa_experiment::IOutsideExecutionV2DispatcherTrait;
    
    use aa_experiment::SessionEntrypoint;
    use aa_experiment::Call;
    use aa_experiment::SessionKey;
    use aa_experiment::OutsideExecution;
    use aa_experiment::mock::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};
    use aa_experiment::mock::{IReentrancyProbeDispatcher, IReentrancyProbeDispatcherTrait};

    fn calculate_outside_execution_hash(address: ContractAddress, chain_id: felt252, outside_execution: OutsideExecution) -> felt252{
       hash_outside_execution_message(address, @outside_execution, chain_id)
    }


    #[test]
    fn test_checking_multisig() {
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor, first element is len of array [1, 2, 3, 4]
        let constructor_calldata = array![4, 1, 2, 3, 4, 4];

        // deploy AA and get address
        let (contract_address, _) = contract
            .deploy(@constructor_calldata)
            .unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {
            contract_address,
        };

        assert!(dispatcher.get_public_keys(1), "There isn't this key in multisig allow");
        assert!(dispatcher.get_public_keys(2), "There isn't this key in multisig allow");
        assert!(dispatcher.get_public_keys(3), "There isn't this key in multisig allow");
        assert!(dispatcher.get_public_keys(4), "There isn't this key in multisig allow");
        assert!(!dispatcher.get_public_keys(5), "There isn't this key in multisig allow");
        assert!(!dispatcher.get_public_keys(6), "There isn't this key in multisig allow");

        assert!(dispatcher.get_threshold() != 3, "musn't be equal");
        assert!(dispatcher.get_threshold() == 4, "must be 4");
        assert!(dispatcher.get_threshold() != 5, "musn't be equal");
    }

    #[test]
    fn test_replace_owner(){
         let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let constructor_calldata = array![3, 1, 2, 3, 2];

        // deploy AA and get address
        let (contract_address, _) = contract
            .deploy(@constructor_calldata)
            .unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {
            contract_address,
        };

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_guardian(0x777);
        stop_cheat_caller_address(contract_address);
        start_cheat_caller_address(contract_address, 0x777);
        dispatcher.replace_owner(2, 4);
        dispatcher.replace_owner(4, 5);
        stop_cheat_caller_address(0x777);
        let owners = dispatcher.get_public_keys_arr();

        assert!(owners.len() == 3, "wrong owners length");
        assert!(*owners.at(0) == 1, "wrong owner at index 0");
        assert!(*owners.at(1) == 5, "wrong owner at index 1");
        assert!(*owners.at(2) == 3, "wrong owner at index 2");
        assert!(dispatcher.get_public_keys(1), "Invalid pub key");
        assert!(!dispatcher.get_public_keys(2), "Invalid pub key");
        assert!(dispatcher.get_public_keys(3), "Invalid pub key");
        assert!(!dispatcher.get_public_keys(4), "Invalid pub key");
        assert!(dispatcher.get_public_keys(5), "Invalid pub key");
        assert!(dispatcher.get_threshold() == 2, "threshold must be 2");

    }

    #[test]
    fn test_checking_multisig_same_keys() {
        let contract = declare("aa_experiment::AA").unwrap().contract_class();

        let constructor_calldata = array![3, 1, 1, 2, 2];

        let deploy_result = contract.deploy(@constructor_calldata);

        assert!(deploy_result.is_err(), "deployment must fail");
    }

    #[test]
    fn test_replace_owner_that_has_session_key(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
      
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let guardian: ContractAddress = 0x007;
    
        let session_contract_a = SessionEntrypoint{target_contract: 0x04043, selector: selector!("transfer")};
        let empty_session_key = SessionKey { expires_at: 0, max_calls: 0, calls_used: 0, allowed_entrypoints_len: 0};
        
        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        dispatcher.add_guardian(guardian);
        stop_cheat_caller_address(contract_address);
        start_cheat_caller_address(contract_address, guardian);
        dispatcher.replace_owner(1, key_felt);
        assert!(dispatcher.get_public_keys(key_felt), "key felt must be the new owner");
        assert!(!dispatcher.get_public_keys(1), "1 must not be owner");
        assert!(dispatcher.get_session_key(key_felt).expires_at == empty_session_key.expires_at, "expires at must be emppty");
        assert!(dispatcher.get_session_key(key_felt).max_calls == empty_session_key.max_calls, "max calls must be emppty");
        assert!(dispatcher.get_session_key(key_felt).calls_used == empty_session_key.calls_used, "calls used must be emppty");
        assert!(dispatcher.get_session_key(key_felt).allowed_entrypoints_len == empty_session_key.allowed_entrypoints_len, "allowed entrypoints must be emppty");
    }

     #[test]
    fn test_replace_owner_and_nullify_all_in_new_owner(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
      
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let guardian: ContractAddress = 0x007;
    
        let session_contract_a = SessionEntrypoint{target_contract: 0x04043, selector: selector!("transfer")};
        
        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, 0x04043, 10000000, 25000000, 50000000, 20000);
        dispatcher.set_spending_policy(key_felt, 0x04340, 10000000, 25000000, 50000000, 20000);
        dispatcher.add_guardian(guardian);
        stop_cheat_caller_address(contract_address);
        start_cheat_caller_address(contract_address, guardian);
        dispatcher.replace_owner(1, key_felt);
        assert!(!dispatcher.get_public_keys(1), "1 must be ex-owner");
        assert!(dispatcher.get_public_keys(key_felt), "key felt must be new owner");
        assert!(dispatcher.get_session_key(key_felt).expires_at == 0, "expires at must be zero");
        assert!(dispatcher.get_session_key(key_felt).max_calls == 0, "max calls must be zero");
        assert!(dispatcher.get_session_key(key_felt).allowed_entrypoints_len == 0, "entrypoints len must be zero");
        let entrypoints = dispatcher.get_allowed_entrypoints(key_felt);
        assert!(entrypoints.len() == 0, "entrypoints array must be empty");
        assert!(!dispatcher.get_spending_policy(key_felt, 0x04043).is_configured, "first token spending policy musn't be configured");
        assert!(!dispatcher.get_spending_policy(key_felt, 0x04340).is_configured, "second token spending policy musn't be configured");
        assert!(dispatcher.get_policy_tokens(key_felt).len() == 0, "policy tokens arr must be empty");
    }

    #[test]
    fn test_validate_and_execute_together_with_session_key_and_spending_policy(){
    
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();

        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
        let mock_dispatcher_usdc = IMockERC20Dispatcher { contract_address: usdc };
        mock_dispatcher_usdc.mint(contract_address, 100000000_u256);
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0].span()};
        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0].span()};

        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 10000000, 20000000, 30000000, 20000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        let validate_res = account.__validate__(array![call]);
        assert!(validate_res == starknet::VALIDATED, "not validated");
        assert!(dispatcher.get_session_key(key_felt).calls_used == 1, "calls used must be 1 after validating");
        account.__execute__(array![call_1]);
        assert!(dispatcher.get_session_key(key_felt).calls_used == 1, "calls used must be 1 after execution");

        assert!(mock_dispatcher_usdc.balance_of(0x02034) == 3000000, "Invalid recipient balance");
        assert!(mock_dispatcher_usdc.balance_of(contract_address) == 100000000 - 3000000, "Invalid recipient balance");
        let usdc_policy = dispatcher.get_spending_policy(key_felt, usdc);

        assert!(usdc_policy.spent_in_window == 3000000, "USDC spending not recorded");

    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_validate_with_rejected_execution(){
    
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();

        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
        let account_safe = IAccountSafeDispatcher { contract_address:  contract_address};

        let mock_dispatcher_usdc = IMockERC20Dispatcher { contract_address: usdc };
        mock_dispatcher_usdc.mint(contract_address, 1000000_u256);
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0].span()};
        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0].span()};

        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 4000000, 8000000, 10000000, 20000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        let validate_res = account.__validate__(array![call]);
        assert!(validate_res == starknet::VALIDATED, "not validated");
        assert!(dispatcher.get_session_key(key_felt).calls_used == 1, "calls used must be 1 after validating");
        let execute_res = account_safe.__execute__(array![call_1]);
        
        match execute_res{
            Result::Ok(_) => {
                assert!(false, "Execution should have failed")
            },
            Result::Err(_) => {}
        }
        assert!(dispatcher.get_session_key(key_felt).calls_used == 1, "calls used must be 1 after execution");
        let usdc_policy = dispatcher.get_spending_policy(key_felt, usdc);
        assert!(usdc_policy.spent_in_window == 0, "USDC spending not recorded");
        assert!(mock_dispatcher_usdc.balance_of(contract_address) == 1000000, "balance of aa must be 1 USDC");
        assert!(mock_dispatcher_usdc.balance_of(0x02034) == 0, "balance of 0x02034 must be 0 USDC");

    }

    #[test]
    fn test_checking_src_5(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let constructor_calldata = array![3, 1, 2, 3, 2];

        let (_contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        let dispatcher = ISRC5Dispatcher { contract_address: _contract_address};
        assert!(dispatcher.supports_interface(0x3f918d17e5ee77373b56385708f855659a07f75997f365cf87748628532a055), "SRC-5 must be supported");
        assert!(dispatcher.supports_interface(0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd), "SRC-6 must be supported");
        assert!(!dispatcher.supports_interface(0x92980948032ab3843874da9483284092804eb498493849389483984bdc345), "Unknown interface must not be supported");
    }

    #[test]
    fn test_checking_multisig_with_is_valid_signature(){
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);

        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(2987235);

        let key_felt_a = key_pair_a.public_key;
        let key_felt_b = key_pair_b.public_key;
       
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![2, key_felt_a, key_felt_b, 2];

        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        let account = IAccountDispatcher { contract_address:  contract_address};

        let tx_hash = 0x123456;
        let (r_a, s_a) = key_pair_a.sign(tx_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(tx_hash).unwrap();
        let (r_wrong, s_wrong) = key_pair_b.sign(0x483782).unwrap();

        

        let signature = array![key_felt_a, r_a, s_a, key_felt_b, r_b, s_b];
        let is_valid_sig = account.is_valid_signature(tx_hash, signature);
        assert!(is_valid_sig == starknet::VALIDATED, "signature must be validated");
        let wrong_valid = account.is_valid_signature(tx_hash, array![key_felt_a, r_a, s_a, key_felt_a, r_a, s_a]);
        assert!(wrong_valid != starknet::VALIDATED, "wrong sig musn't be validated");
        let wrong_valid_1 = account.is_valid_signature(tx_hash, array![key_felt_a, r_a, s_a, key_felt_b, r_wrong, s_wrong]);
        assert!(wrong_valid_1 == 0, "wrong sig musn't be validated");
    }

    // testing SNIP 9 sig
    #[test]
    fn test_unused_nonce_is_available(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![2, 1, 2, 2];

        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        let dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };

        assert!(dispatcher.is_valid_outside_execution_nonce(0x032342), "message");
    }

    // < temporary test
    #[test]
    fn test_checking_hashings_helpers(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![2, 1, 2, 2];

        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        let call_a = StarknetCall { to: 0x111, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let call_b = StarknetCall { to: 0x333, selector: selector!("approve"), calldata:  array![0x444, 0x5678, 200000000].span()};

        let outside_execution = OutsideExecution { caller: 0x777, nonce: 0x12345, execute_after: 1000, execute_before: 2000, calls:  array![call_a, call_b].span()};
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let cairo_hash =  calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);
        stop_cheat_chain_id(contract_address);
        println!("ACCOUNT: 0x{:x}", contract_address);
        println!("CAIRO HASH: 0x{:x}", cairo_hash);

    }
    // >

    #[test]
    fn test_outside_execution(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let (dai, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        let dai_dispatcher = IMockERC20Dispatcher { contract_address: dai};

        usdc_dispatcher.mint(contract_address, 100000000_u256);
        
        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        
        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let call_b = StarknetCall { to: dai, selector: selector!("approve"), calldata:  array![0x444, 200000000, 0].span()};
        
        let allowed_caller = 0x007;
        let nonce = 0x020304;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a, call_b].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce),"Nonce must be available before execution");
        let res = outside_execution_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        assert!(res.len() == 2, "Both calls must return results");
        assert!(usdc_dispatcher.balance_of(contract_address) == 0, "must be zeor balance");
        assert!(usdc_dispatcher.balance_of(0x222) == 100000000, "must be 100000000");
        assert!(dai_dispatcher.allowance(contract_address, 0x444) == 200000000, "allowance must be 200000000");
        assert!(!outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce is not available");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_insufficient_signatures(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller = 0x007;
        let nonce = 0x020304;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res {
             Result::Ok(_) => {
             assert!(false, "outside executin should have failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA hasn't be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of recipient must be 0");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_replayed_nonce(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller = 0x007;
        let nonce = 0x020304;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        outside_execution_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        assert!(!outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must not be available after execution");
        let recipient_balance = usdc_dispatcher.balance_of(0x222);
        assert!(recipient_balance == 100000000, "First execution must transfer tokens");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());

        match res{
            Result::Ok(_) => {
             assert!(false, "outside executin should have failed");
            },
            Result::Err(_) => {}
        }
        assert!(usdc_dispatcher.balance_of(0x222) == recipient_balance, "Balance of recipient musnt't be changed after second execution");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_wrong_caller(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller = 0x007;
        let wrong_caller = 0x008;
        let nonce = 0x020304;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, wrong_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "must be false");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must remain available after rejection");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA hasn't be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of recipient must be 0");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_before_execute_after(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller = 0x007;
        let nonce = 0x020304;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 1500);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "must be false");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must remain available after rejection");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA hasn't be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of recipient must be 0");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_after_execute_before(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller = 0x007;
        let nonce = 0x020304;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2500);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "must be false");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must remain available after rejection");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA hasn't be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of recipient must be 0");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rollbacks_on_failed_call(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let call_b = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0xDEAD, 100000000, 0].span()};


        let allowed_caller = 0x007;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a, call_b].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "must be false");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA hasn't be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of recipient must be 0");
    }

    #[test]
    fn test_outside_execution_accepts_any_caller(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};


        let any_caller: ContractAddress = 0x414e595f43414c4c4552; //0x414e595f43414c4c4552 is ANY_CALLER constant in contract
        let actual_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: any_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, actual_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash = calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        outside_execution_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        assert!(usdc_dispatcher.balance_of(contract_address) == 0, "balance of AA must be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 100000000, "balance of recipient must be 100000000");
        assert!(!outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce mustn't be available after execution");
    }

    #[test]
    fn test_outside_execution_with_empty_calls(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };

        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        assert!(res.len() == 0, "result must have zero items in returned arr");
        assert!(!outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must not be available after execution");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_invalid_ecdsa_signature(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };

        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(0x0305048437).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "expected false res");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available after rejected execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA hasn't be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of recipient must be 0");
    }

    #[test]
    fn test_outside_execution_ignores_invalid_signature_before_valid_one(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };

        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a_invalid, s_a_invalid) = key_pair_a.sign(0x03847373).unwrap();
        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a_invalid, s_a_invalid, key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        outside_execution_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
       
        assert!(!outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must not be available after execution");
        assert!(usdc_dispatcher.balance_of(0x222) == 100000000, "balance of recipient must recieve 100000000");
        assert!(usdc_dispatcher.balance_of(contract_address) == 0, "balance of AA must be 0 after success transfer");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_duplicate_owner_signatures(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let signature =  array![key_a_felt, r_a, s_a, key_a_felt, r_a, s_a,];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "transaction must be failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must not be available after invalid execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of 0x222 must be 0 after failed transfer");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_non_owner_signature(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
        let key_pair_c =
        KeyPairTrait::<felt252, felt252>::from_secret_key(38275873);

        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;
        let key_c_felt = key_pair_c.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_c, s_c) = key_pair_c.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_c_felt, r_c, s_c];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "transaction must be failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must not be available after invalid execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of 0x222 must be 0 after failed transfer");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_malformed_signature_length(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
      
        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, _) = key_pair_b.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "transaction must be failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must not be available after invalid execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of 0x222 must be 0 after failed transfer");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_modified_calls(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
      
        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};
        let call_b = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x333, 100000000, 0].span()};

        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        let another_outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_b].span() };

        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(another_outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "transaction must be failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must not be available after invalid execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of 0x222 must be 0 after failed transfer");
        assert!(usdc_dispatcher.balance_of(0x333) == 0, "balance of 0x333 must be 0 after failed transfer");

    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_cross_account_replay(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
      
        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (contract_address_1, _) = contract.deploy(@constructor_calldata).unwrap();

        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);
        usdc_dispatcher.mint(contract_address_1, 100000000_u256);


        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_dispatcher_1 = IOutsideExecutionV2Dispatcher { contract_address: contract_address_1 };
        let outside_execution_safe_dispatcher_1 = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address_1 };

        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller: ContractAddress = 0x008;
        let nonce = 0x020305;
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };

        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        start_cheat_caller_address(contract_address_1, allowed_caller);
        start_cheat_block_timestamp(contract_address_1, 2000);
        start_cheat_chain_id(contract_address_1, 'SN_SEPOLIA');
        let message_hash_1 =   calculate_outside_execution_hash(contract_address_1, 'SN_SEPOLIA', outside_execution);
        assert!(message_hash != message_hash_1, "Different accounts must produce different message hashes");
        
        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce of first AA must be available before execution");
        assert!(outside_execution_dispatcher_1.is_valid_outside_execution_nonce(nonce), "Nonce of second AA must be available before execution");
        let res = outside_execution_safe_dispatcher_1.execute_from_outside_v2(outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "transaction must be failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce of first AA must be available after invalid execution");
        assert!(outside_execution_dispatcher_1.is_valid_outside_execution_nonce(nonce), "Nonce of second AA must remain available after rejected execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(contract_address_1) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of 0x222 must be 0 after failed transfer");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_modified_caller(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
      
        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller = 0x007;
        let actual_caller = 0x008;
        let any_caller = 0x414e595f43414c4c4552;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        let another_outside_execution = OutsideExecution { caller: any_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };

        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        start_cheat_caller_address(contract_address, actual_caller);
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(another_outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "transaction must be failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must remain available after rejected execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of 0x222 must be 0 after failed transfer");
    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_modified_execute_before(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
      
        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x222, 100000000, 0].span()};

        let allowed_caller = 0x007;
        let nonce = 0x020305;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        let another_outside_execution = OutsideExecution { caller: allowed_caller, nonce: nonce, execute_after: 1500, execute_before: 3000, calls: array![call_a].span() };

        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must be available before execution");
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(another_outside_execution, signature.span());
        match res{
            Result::Ok(_) => {
                assert!(false, "transaction must be failed");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(nonce), "Nonce must remain available after rejected execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x222) == 0, "balance of 0x222 must be 0 after failed transfer");
    }

    #[test]
    fn test_outside_execution_blocks_reentrancy(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let reentracy_contract = declare("ReentrancyProbe").unwrap().contract_class();

        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
      
        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;
        let any_caller = 0x414e595f43414c4c4552;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);
        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };

        let (reentracy_probe, _) = reentracy_contract.deploy(@array![]).unwrap();
        let reentracy_prove_dispatcher = IReentrancyProbeDispatcher { contract_address: reentracy_probe };

        let amount: u256 = 100000000;
        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x333, 100000000, 0].span()};
        let reentracy_outside_execution = OutsideExecution { caller: any_caller, nonce: 0x020309, execute_after: 1500, execute_before: 2500, calls:  array![call_a].span()};
        start_cheat_caller_address(contract_address, 0x007);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =  calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', reentracy_outside_execution);
        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();

        let inner_signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        let mut probe_calldata: Array<felt252> = array![
            contract_address.into(),
            usdc.into(),
            0x333,
            amount.low.into(),
            amount.high.into(),
            0x020309,
            1500,
            2500,
            inner_signature.len().into()
        ];
        for value in inner_signature.span() {
            probe_calldata.append(*value);
        }
        let reentracy_call = StarknetCall {to: reentracy_probe, selector: selector!("attempt_reentry"), calldata: probe_calldata.span()};
        let outside_execution = OutsideExecution { caller: 0x007, nonce: 0x020309, execute_after: 1500, execute_before: 2500, calls: array![reentracy_call].span() };
        let hash_outside_execution =  calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);
        let (r_a_1, s_a_1) = key_pair_a.sign(hash_outside_execution).unwrap();
        let (r_b_1, s_b_1) = key_pair_b.sign(hash_outside_execution).unwrap();
        let outer_signature = array![key_a_felt, r_a_1, s_a_1, key_b_felt, r_b_1, s_b_1];

        outside_execution_dispatcher.execute_from_outside_v2(outside_execution, outer_signature.span());
        assert!(reentracy_prove_dispatcher.was_reentry_rejected(), "reentracy must be rejected");
        assert!(!outside_execution_dispatcher.is_valid_outside_execution_nonce(0x020309), "Nonce must not be available after execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x333) == 0, "balance of 0x333 must be 0 after failed transfer");

    }

    #[feature("safe_dispatcher")]
    #[test]
    fn test_outside_execution_rejects_modified_nonce(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        let key_pair_a =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
        let key_pair_b =
        KeyPairTrait::<felt252, felt252>::from_secret_key(9384759);
      
        let key_a_felt = key_pair_a.public_key;
        let key_b_felt = key_pair_b.public_key;

        // put calldata of constructor
        let constructor_calldata = array![2, key_a_felt, key_b_felt, 2];
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let usdc_dispatcher = IMockERC20Dispatcher { contract_address: usdc};
        usdc_dispatcher.mint(contract_address, 100000000_u256);

        let outside_execution_dispatcher = IOutsideExecutionV2Dispatcher { contract_address: contract_address };
        let outside_execution_safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: contract_address };


        let call_a = StarknetCall { to: usdc, selector: selector!("transfer"), calldata:  array![0x001, 100000000, 0].span()};

        let allowed_caller = 0x007;
        // deploy AA and get address
        let outside_execution = OutsideExecution { caller: allowed_caller, nonce: 0x111, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };
        let another_outside_execution = OutsideExecution { caller: allowed_caller, nonce: 0x222, execute_after: 1500, execute_before: 2500, calls: array![call_a].span() };

        start_cheat_caller_address(contract_address, allowed_caller);
        start_cheat_block_timestamp(contract_address, 2000);
        start_cheat_chain_id(contract_address, 'SN_SEPOLIA');
        let message_hash =   calculate_outside_execution_hash(contract_address, 'SN_SEPOLIA', outside_execution);

        let (r_a, s_a) = key_pair_a.sign(message_hash).unwrap();
        let (r_b, s_b) = key_pair_b.sign(message_hash).unwrap();

        let signature =  array![key_a_felt, r_a, s_a, key_b_felt, r_b, s_b];
        let res = outside_execution_safe_dispatcher.execute_from_outside_v2(another_outside_execution, signature.span());
        match res {
            Result::Ok(_) => {
                assert!(false, "Expected false for Result::Ok");
            },
            Result::Err(_) => {}
        }
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(0x111), "Nonce 0x111 must remain available after rejected execution");
        assert!(outside_execution_dispatcher.is_valid_outside_execution_nonce(0x222), "Nonce 0x222 must remain available after rejected execution");
        assert!(usdc_dispatcher.balance_of(contract_address) == 100000000, "balance of AA must not be changed");
        assert!(usdc_dispatcher.balance_of(0x001) == 0, "balance of 0x001 must be 0 after failed transfer");
    }


}