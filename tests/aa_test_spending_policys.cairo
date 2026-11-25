use snforge_std::cheatcodes::execution_info::contract_address;

#[cfg(test)]

mod test{
    use super::contract_address;
    use core::num::traits::Zero;
    use snforge_std::start_cheat_signature;
    use starknet::ContractAddress;
    use snforge_std::{start_cheat_transaction_hash, start_cheat_block_timestamp, stop_cheat_block_timestamp,
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address, stop_cheat_caller_address, 
    start_cheat_transaction_version};
    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl,
    StarkCurveSignerImpl
    };
    
    // use aa_experiment::AA;
    use aa_experiment::IAccountManagementDispatcher;
    use aa_experiment::IAccountManagementDispatcherTrait;
    use aa_experiment::IAccountDispatcher;
    use aa_experiment::IAccountDispatcherTrait;
    use aa_experiment::mock::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};
    use aa_experiment::SessionEntrypoint;
    use aa_experiment::Call;

    #[should_panic(expected: "from must be self address in transfer from")]
    #[test]
    fn test_transfer_from_from_is_not_right(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract
            .deploy(@constructor_calldata)
            .unwrap();
    
        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {
            contract_address,
        };
    
        let account = IAccountDispatcher { contract_address:  contract_address};
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
    
        let usdc: ContractAddress = 0x12345;
        let random_address = 0x0092dc3ab2;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer_from")};
        let call = Call { to: usdc, selector: selector!("transfer_from"), calldata: array![random_address, 0x02034, 6000000, 0].span() };
        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 7200, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 40000000, 100000000, 600000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call]);

    }

    #[should_panic(expected: "Spending: exceeds per-call limit")]
    #[test]
    fn test_wrong_max_per_call(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract
            .deploy(@constructor_calldata)
            .unwrap();
    
        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {
            contract_address,
        };
    
        let account = IAccountDispatcher { contract_address:  contract_address};
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair =
        KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
    
        let usdc: ContractAddress = 0x12345;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};
        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 7200, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 4000000, 100000000, 600000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call]);

    }

    #[should_panic(expected: "Spending: exceeds transaction limit")]
    #[test]
    fn test_wrong_max_per_transaction(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    
        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
        
        let usdc: ContractAddress = 0x12345;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};
        let call_2 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};

        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 7200, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 8000000, 10000000, 20000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call_1, call_2]);
    }

    #[should_panic(expected: "Spending: exceeds window limit")]
    #[test]
    fn test_wrong_max_per_window(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (mock_address, _) = mock.deploy(@array![]).unwrap();
        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
        let mock_dispatcher = IMockERC20Dispatcher { contract_address: mock_address };
        mock_dispatcher.mint(contract_address, 100000000_u256);
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
    
        let usdc: ContractAddress = mock_address;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};
        let call_2 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};

        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 7200, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 8000000, 8000000, 10000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call_1]);
        account.__execute__(array![call_2]);
    }

    #[test]
    fn test_call_after_expired_window(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (mock_address, _) = mock.deploy(@array![]).unwrap();
        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
        let mock_dispatcher = IMockERC20Dispatcher { contract_address: mock_address };
        mock_dispatcher.mint(contract_address, 100000000_u256);
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
    
        let usdc: ContractAddress = mock_address;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};
        let call_2 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};

        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        start_cheat_block_timestamp(contract_address, 1000);
        dispatcher.set_spending_policy(key_felt, usdc, 8000000, 8000000, 10000000, 10000);
        stop_cheat_caller_address(contract_address);
        stop_cheat_block_timestamp(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call_1]);
        start_cheat_block_timestamp(contract_address, 11000);
        account.__execute__(array![call_2]);
        stop_cheat_block_timestamp(contract_address);
    }

    #[should_panic(expected: "Spending: allowance operations disabled")]
    #[test]
    fn test_rejected_approve_in_spending_policy(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (mock_address, _) = mock.deploy(@array![]).unwrap();
        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
        let mock_dispatcher = IMockERC20Dispatcher { contract_address: mock_address };
        mock_dispatcher.mint(contract_address, 100000000_u256);
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
    
        let usdc: ContractAddress = mock_address;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("approve")};
        let call_1 = Call { to: usdc, selector: selector!("approve"), calldata: array![0x02034, 60000000, 0].span()};

        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 8000000, 8000000, 10000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call_1]);
    }


    #[test]
    fn test_spending_policy_between_two_different_tokens(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let mock = declare("MockERC20").unwrap().contract_class();

        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        let (usdc, _) = mock.deploy(@array![]).unwrap();
        let (dai, _) = mock.deploy(@array![]).unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
        let mock_dispatcher_usdc = IMockERC20Dispatcher { contract_address: usdc };
        let mock_dispatcher_dai = IMockERC20Dispatcher { contract_address: dai };
        mock_dispatcher_usdc.mint(contract_address, 100000000_u256);
        mock_dispatcher_dai.mint(contract_address, 100000000_u256);
    
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
    
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let session_contract_b = SessionEntrypoint{target_contract: dai, selector: selector!("transfer")};

        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 6000000, 0].span()};
        let call_2 = Call { to: dai, selector: selector!("transfer"), calldata: array![0x02034, 100000000, 0].span()};


        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a, session_contract_b]);
        dispatcher.set_spending_policy(key_felt, usdc, 8000000, 8000000, 10000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call_1, call_2]);

        assert!(mock_dispatcher_usdc.balance_of(0x2034) == 6000000, "Invalid recipient balance");
        assert!(mock_dispatcher_dai.balance_of(0x2034) == 100000000, "Invalid recipient balance");
        assert!(mock_dispatcher_usdc.balance_of(contract_address) == 100000000 - 6000000, "Invalid recipient balance");
        assert!(mock_dispatcher_dai.balance_of(contract_address) == 0, "Invalid recipient balance");
        let usdc_policy = dispatcher.get_spending_policy(key_felt, usdc);
        let dai_policy = dispatcher.get_spending_policy(key_felt, dai);

        assert!(usdc_policy.spent_in_window == 6000000, "USDC spending not recorded");
        assert!(!dai_policy.is_configured, "DAI policy should not be configured");

    }

    #[test]
    fn test_seccess_batch_of_token(){
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

        let call_1 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0].span()};
        let call_2 = Call { to: usdc, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0].span()};


        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, usdc, 4000000, 8000000, 10000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        account.__execute__(array![call_1, call_2]);

        assert!(mock_dispatcher_usdc.balance_of(0x2034) == 6000000, "Invalid recipient balance");
        assert!(mock_dispatcher_usdc.balance_of(contract_address) == 100000000 - 6000000, "Invalid recipient balance");
        let usdc_policy = dispatcher.get_spending_policy(key_felt, usdc);

        assert!(usdc_policy.spent_in_window == 6000000, "USDC spending not recorded");

    }

    #[should_panic(expected: "Unsupported transaction version")]
    #[test]
    fn test_execute_with_wrong_tx_version(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        // put calldata of constructor
        let constructor_calldata = array![3, 1, 2, 3, 2];
    
        // deploy AA and get address
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();

        // create dispatcher
        let dispatcher = IAccountManagementDispatcher {contract_address,};
        let account = IAccountDispatcher { contract_address:  contract_address};
      
        // creating pair where 1234567 is testing private key, not real
        let key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(1234567);
    
        //getting its public key, hash and start cheating
        let key_felt = key_pair.public_key;
        let tx_hash = 0x123456;
        let (r, s) = key_pair.sign(tx_hash).unwrap();
    
        let session_contract_a = SessionEntrypoint{target_contract: 0x04043, selector: selector!("transfer")};

        let call = Call { to: 0x04043, selector: selector!("transfer"), calldata: array![0x02034, 3000000, 0].span()};


        let signature = array![key_felt, r, s].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a]);
        dispatcher.set_spending_policy(key_felt, 0x04043, 4000000, 8000000, 10000000, 10000);
        stop_cheat_caller_address(contract_address);

        start_cheat_transaction_hash(contract_address, tx_hash);
        start_cheat_signature(contract_address, signature);
        start_cheat_caller_address(contract_address, Zero::zero());
        start_cheat_transaction_version(contract_address, 0);
        account.__execute__(array![call]);
    }

    #[test]
    fn test_changing_and_removing_spending_policy(){
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
        let usdc = 0x04043;
        let dai = 0x04340;
    
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let session_contract_b = SessionEntrypoint{target_contract: dai, selector: selector!("transfer")};

        
        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(key_felt, 36000, 4, array![session_contract_a, session_contract_b]);
        dispatcher.set_spending_policy(key_felt, usdc, 10000000, 25000000, 50000000, 20000);
        dispatcher.set_spending_policy(key_felt, dai, 10000000, 25000000, 50000000, 20000);
        dispatcher.set_spending_policy(key_felt, usdc, 5000000, 20000000, 25000000, 25000); 
        let tokens = dispatcher.get_policy_tokens(key_felt);
        assert!(tokens.len() == 2, "must contain two tokens");
        let first = *tokens.at(0);
        let second = *tokens.at(1);
        assert!((first == usdc && second == dai) || (first == dai && second == usdc), "must contain USDC and DAI exactly once");
        dispatcher.remove_spending_policy(key_felt, usdc);
        assert!(!dispatcher.get_spending_policy(key_felt, usdc).is_configured, "spending policy for usdc musn't be configured");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).max_per_call == 0, "all targets of spending policy for usdc must be off");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).max_per_transaction == 0, "all targets of spending policy for usdc must be off");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).max_per_window == 0, "all targets of spending policy for usdc must be off");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).window_seconds == 0, "all targets of spending policy for usdc must be off");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).window_start == 0, "all targets of spending policy for usdc must be off");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).spent_in_window == 0, "all targets of spending policy for usdc must be off");
        assert!(dispatcher.get_spending_policy(key_felt, dai).is_configured, "spending policy for dai musn't have changed");
        assert!(dispatcher.get_policy_tokens(key_felt).len() == 1 && *dispatcher.get_policy_tokens(key_felt).at(0) == dai, "policy tokens arr must have only 1 items and it must be dai");
        dispatcher.set_spending_policy(key_felt, usdc, 1000000, 2000000, 3000000, 20000);
        let tokens = dispatcher.get_policy_tokens(key_felt);
        assert!(tokens.len() == 2, "must contain two tokens");
        assert!((first == usdc && second == dai) || (first == dai && second == usdc), "must contain USDC and DAI exactly once");

        assert!(dispatcher.get_spending_policy(key_felt, usdc).is_configured, "spending policy for usdc must be configured");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).max_per_call == 1000000, "all targets of spending policy for usdc must be on");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).max_per_transaction == 2000000, "all targets of spending policy for usdc must be on");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).max_per_window == 3000000, "all targets of spending policy for usdc must be on");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).window_seconds == 20000, "all targets of spending policy for usdc must be on");
        assert!(dispatcher.get_spending_policy(key_felt, usdc).spent_in_window == 0, "all targets of spending policy for usdc must be on");
    }



}