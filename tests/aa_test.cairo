#[cfg(test)]
mod tests{
    use snforge_std::start_cheat_signature;
    use starknet::ContractAddress;
    use snforge_std::{stop_cheat_caller_address_global, cheat_caller_address,
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address, stop_cheat_caller_address};
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
    use aa_experiment::SessionEntrypoint;
    use aa_experiment::Call;

    #[test]
    fn test_deploy_aa() {
        let contract = declare("aa_experiment::AA").unwrap().contract_class();
        let constructor_calldata = array![3, 1, 2, 3, 2];

        let (_contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    }

    #[test]
    fn test_add_session_key() {
        // get class AA
        let contract = declare("aa_experiment::AA").unwrap().contract_class();

        let session_contract = SessionEntrypoint{target_contract: 0x012345, selector: selector!("transfer")};
        let session_contract_1 = SessionEntrypoint{target_contract: 0x012345, selector: selector!("approve")};
        let session_contract_2 = SessionEntrypoint{target_contract: 0x54321, selector: selector!("swap")};
        let session_contract_3 = SessionEntrypoint { target_contract: 0x0001, selector:  selector!("approve")};

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

        // call contract fn from itself
        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(100, 4000, 5, array![session_contract, session_contract_1, session_contract_2, session_contract_3]);
        stop_cheat_caller_address(contract_address);
        let session_key = dispatcher.get_session_key(100);
        let allowed_entrypoints = dispatcher.get_allowed_entrypoints(100);
        assert!(session_key.expires_at == 4000, "expires at must be 4000");
        assert!(session_key.max_calls == 5, "max calls must be 5");
        assert!(session_key.calls_used == 0, "calls used must be zero");
        assert!(session_key.allowed_entrypoints_len == 4, "must be 4");
        assert!(*allowed_entrypoints.at(0).selector == selector!("transfer"), "must be same");
        assert!(*allowed_entrypoints.at(1).selector == selector!("approve"), "must be same");
        assert!(*allowed_entrypoints.at(2).selector == selector!("swap"), "must be same");
        assert!(*allowed_entrypoints.at(0).target_contract == 0x012345, "wrong target");
        assert!(*allowed_entrypoints.at(1).target_contract == 0x012345, "wrong target");
        assert!(*allowed_entrypoints.at(2).target_contract == 0x54321, "wrong target");
        assert!(*allowed_entrypoints.at(3).target_contract == 0x0001, "wrong target");
        assert!(*allowed_entrypoints.at(3).selector == selector!("approve"), "wrong selector");
        assert!(allowed_entrypoints.len() == 4, "wrong array length");

        start_cheat_caller_address(contract_address, contract_address);
         dispatcher.add_session_key(100, 3000, 3, array![session_contract, session_contract_1]);
        stop_cheat_caller_address(contract_address);
        let new_session_key = dispatcher.get_session_key(100);
        let new_allowed_entrypoints = dispatcher.get_allowed_entrypoints(100);
        assert!(new_allowed_entrypoints.len() == 2, "wrong array length");
        assert!(new_session_key.allowed_entrypoints_len == 2, "must be 2");
        assert!(new_session_key.max_calls == 3, "must be 3");
        assert!(new_session_key.calls_used == 0, "must be 0");
        assert!(new_session_key.expires_at == 3000, "must be 3000");
        assert!(*new_allowed_entrypoints.at(0).target_contract == 0x012345, "wrong target");
        assert!(*new_allowed_entrypoints.at(1).target_contract == 0x012345, "wrong target");
        assert!(*new_allowed_entrypoints.at(0).selector == selector!("transfer"), "first selector must be transfer");
        assert!(*new_allowed_entrypoints.at(1).selector == selector!("approve"), "second selector must be approve");
    }

    #[test]
    fn test_updating_session_key_does_not_modify_another_session(){
         // get class AA
        let contract = declare("aa_experiment::AA").unwrap().contract_class();

        let session_contract = SessionEntrypoint{target_contract: 0x012345, selector: selector!("transfer")};
        let session_contract_1 = SessionEntrypoint{target_contract: 0x012345, selector: selector!("approve")};
        let session_contract_2 = SessionEntrypoint{target_contract: 0x54321, selector: selector!("swap")};
        let session_contract_3 = SessionEntrypoint { target_contract: 0x0001, selector:  selector!("approve")};
        let session_contract_4 = SessionEntrypoint { target_contract: 0x15432, selector:  selector!("swap")};
        let session_contract_5 = SessionEntrypoint { target_contract: 0x054431, selector:  selector!("approve")};
        let session_contract_6 = SessionEntrypoint { target_contract: 0x43251, selector:  selector!("transfer")};


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

        // call contract fn from itself
        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(100, 4000, 5, array![session_contract, session_contract_1, session_contract_2, session_contract_3]);
        dispatcher.add_session_key(200, 4500, 3, array![session_contract_4, session_contract_5, session_contract_6]);
        dispatcher.add_session_key(100, 3000, 2, array![session_contract, session_contract_1]);
        stop_cheat_caller_address(contract_address);

        let session_key = dispatcher.get_session_key(100);
        let allowed_entrypoints = dispatcher.get_allowed_entrypoints(100);
        let session_key_1 = dispatcher.get_session_key(200);
        let allowed_entrypoints_1 = dispatcher.get_allowed_entrypoints(200);
        assert!(session_key.allowed_entrypoints_len == 2, "must be 2");
        assert!(session_key.allowed_entrypoints_len == allowed_entrypoints.len(), "must be equal");
        assert!(session_key.expires_at == 3000, "must be 3000");
        assert!(session_key.max_calls == 2, "must be 2");
        assert!(session_key_1.allowed_entrypoints_len == 3, "must be 3");
        assert!(session_key_1.expires_at == 4500, "expires_at must be 4500");
        assert!(session_key_1.max_calls == 3, "max_calls must be 3");
        assert!(session_key_1.calls_used == 0, "calls_used must remain zero");
        assert!(*allowed_entrypoints.at(0).selector == selector!("transfer"), "must be transfer");
        assert!(*allowed_entrypoints.at(1).selector == selector!("approve"), "must be approve");
        assert!(*allowed_entrypoints.at(0).target_contract == 0x012345, "must be 0x012345");
        assert!(*allowed_entrypoints.at(1).target_contract == 0x012345, "must be 0x012345");
        assert!(*allowed_entrypoints_1.at(0).target_contract == 0x15432, "must be 0x15432");
        assert!(*allowed_entrypoints_1.at(1).target_contract == 0x054431, "must be 0x054431");
        assert!(*allowed_entrypoints_1.at(2).target_contract == 0x43251, "must be 0x43251");
        assert!(allowed_entrypoints_1.len() == 3, "wrong array length");

        assert!(*allowed_entrypoints_1.at(0).selector == selector!("swap"), "must be swap");
        assert!(*allowed_entrypoints_1.at(1).selector == selector!("approve"), "must be approve");
        assert!(*allowed_entrypoints_1.at(2).selector == selector!("transfer"), "must be transfer");
    }

    #[test]
    fn test_revoke_session_key(){
        let contract = declare("aa_experiment::AA").unwrap().contract_class();

        let session_contract = SessionEntrypoint{target_contract: 0x012345, selector: selector!("transfer")};
        let session_contract_1 = SessionEntrypoint{target_contract: 0x012345, selector: selector!("approve")};
        let session_contract_2 = SessionEntrypoint{target_contract: 0x54321, selector: selector!("swap")};

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

        // call contract fn from itself
        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(100, 4000, 5, array![session_contract, session_contract_1, session_contract_2]);
        stop_cheat_caller_address(contract_address);
        let session_key = dispatcher.get_session_key(100);
        let allowed_entrypoints = dispatcher.get_allowed_entrypoints(100);
        assert!(session_key.expires_at == 4000, "expires at must be 4000");
        assert!(session_key.max_calls == 5, "max calls must be 5");
        assert!(session_key.calls_used == 0, "calls used must be zero");
        assert!(session_key.allowed_entrypoints_len == 3, "must be 3");
        assert!(*allowed_entrypoints.at(0).selector == selector!("transfer"), "must be same");
        assert!(*allowed_entrypoints.at(1).selector == selector!("approve"), "must be same");
        assert!(*allowed_entrypoints.at(2).selector == selector!("swap"), "must be same");
        assert!(*allowed_entrypoints.at(0).target_contract == 0x012345, "wrong target");
        assert!(*allowed_entrypoints.at(1).target_contract == 0x012345, "wrong target");
        assert!(*allowed_entrypoints.at(2).target_contract == 0x54321, "wrong target");
        assert!(allowed_entrypoints.len() == 3, "wrong array length");

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.revoke_session_key(100);
        stop_cheat_caller_address(contract_address);
        let new_session_key = dispatcher.get_session_key(100);
        let new_allowed_entrypoints = dispatcher.get_allowed_entrypoints(100);
        assert!(new_session_key.expires_at == 0, "expires at must be zero");
        assert!(new_session_key.max_calls == 0, "max calls must be zero");
        assert!(new_session_key.calls_used == 0, "calls used must be zero");
        assert!(new_session_key.allowed_entrypoints_len == 0, "must be zero");
        assert!(new_allowed_entrypoints.len() == 0, "wrong array length");
    }

    #[should_panic(expected: "Only self call allowed")]
    #[test]
    fn test_add_session_key_unauthorized() {
        let contract = declare("aa_experiment::AA").unwrap().contract_class();

        let session_contract = SessionEntrypoint{target_contract: 0x012345, selector: selector!("transfer")};

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

        dispatcher.add_session_key(100, 5500, 3, array![session_contract]);
    }
    #[should_panic(expected: "Only self call allowed")]
    #[test]
    fn test_revoke_session_key_unauthorized(){
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

        dispatcher.revoke_session_key(100);
    }
    
    #[should_panic(expected: "Invalid session key signature")]
    #[test]
    fn test_validate_allowed_entrypoint(){
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

        let usdc: ContractAddress = 0x12345;
        let session_contract = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call = Call { to: usdc, selector: selector!("transfer"), calldata: array![] };
        let fake_signature = array![100, 1, 1].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(100, 4500, 5, array![session_contract]);
        stop_cheat_caller_address(contract_address);

        start_cheat_signature(contract_address, fake_signature);
        account.__validate__(array![call]);
    }

    #[should_panic(expected: "entrypoint isn't allowed")]
    #[test]
    fn test_validate_same_selector_different_contract(){
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

        let usdc: ContractAddress = 0x12345;
        let another_token: ContractAddress = 0x54321;
        let session_contract = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let call = Call { to: another_token, selector: selector!("transfer"), calldata: array![] };
        let fake_signature = array![100, 1, 1].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(100, 4500, 5, array![session_contract]);
        stop_cheat_caller_address(contract_address);

        start_cheat_signature(contract_address, fake_signature);
        account.__validate__(array![call]);
    }

    #[should_panic(expected: "entrypoint isn't allowed")]
    #[test]
    fn test_session_b_cannot_use_session_a_entrypoint(){
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

        let usdc: ContractAddress = 0x12345;
        let dex: ContractAddress = 0x93421;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let session_contract_b = SessionEntrypoint{target_contract: dex, selector: selector!("swap")};

        let call = Call { to: usdc, selector: selector!("transfer"), calldata: array![] };
        let fake_signature = array![200, 1, 1].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(100, 4500, 5, array![session_contract_a]);
        dispatcher.add_session_key(200, 4500, 5, array![session_contract_b]);
        stop_cheat_caller_address(contract_address);

        start_cheat_signature(contract_address, fake_signature);
        account.__validate__(array![call]);
    }

    #[should_panic(expected: "entrypoint isn't allowed")]
    #[test]
    fn test_session_a_cannot_use_session_b_entrypoint(){
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

        let usdc: ContractAddress = 0x12345;
        let dex: ContractAddress = 0x93421;
        let session_contract_a = SessionEntrypoint{target_contract: usdc, selector: selector!("transfer")};
        let session_contract_b = SessionEntrypoint{target_contract: dex, selector: selector!("swap")};

        let call = Call { to: dex, selector: selector!("swap"), calldata: array![] };
        let fake_signature = array![100, 1, 1].span();

        start_cheat_caller_address(contract_address, contract_address);
        dispatcher.add_session_key(100, 4500, 5, array![session_contract_a]);
        dispatcher.add_session_key(200, 4500, 5, array![session_contract_b]);
        stop_cheat_caller_address(contract_address);

        start_cheat_signature(contract_address, fake_signature);
        account.__validate__(array![call]);
    }
   
   

   


}