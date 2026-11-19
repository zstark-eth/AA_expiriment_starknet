use snforge_std::cheatcodes::execution_info::contract_address;

#[cfg(test)]
mod tests{
    use openzeppelin_account::account;
    use snforge_std::start_cheat_signature;
    use starknet::ContractAddress;
    use snforge_std::{start_cheat_transaction_hash,
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address, stop_cheat_caller_address, 
    stop_cheat_signature, stop_cheat_transaction_hash};
    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl,
    StarkCurveSignerImpl
    };
    use core::num::traits::Zero;

    // use aa_experiment::AA;
    use aa_experiment::IAccountManagementDispatcher;
    use aa_experiment::IAccountManagementDispatcherTrait;
    use aa_experiment::IAccountDispatcher;
    use aa_experiment::IAccountDispatcherTrait;
    use aa_experiment::IAccountSafeDispatcher;
    use aa_experiment::IAccountSafeDispatcherTrait;
    use aa_experiment::SessionEntrypoint;
    use aa_experiment::Call;
    use aa_experiment::SessionKey;
    use aa_experiment::mock::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};

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
        let call = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0]};
        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0]};

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
        let call = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0]};
        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0]};

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


}