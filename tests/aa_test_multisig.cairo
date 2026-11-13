use snforge_std::cheatcodes::execution_info::contract_address;

#[cfg(test)]
mod tests{
    use openzeppelin_account::account;
    use snforge_std::start_cheat_signature;
    use starknet::ContractAddress;
    use snforge_std::{stop_cheat_caller_address_global, cheat_caller_address, start_cheat_transaction_hash,
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address, stop_cheat_caller_address, 
    stop_cheat_signature, stop_cheat_transaction_hash};
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


}