use starknet::{ContractAddress};

#[starknet::interface]
 pub trait IMockERC20<TState> {
   fn mint(ref self: TState, to: ContractAddress, amount: u256);
   fn approve(ref self: TState, spender: ContractAddress, amount: u256);
   fn balance_of(self: @TState, account: ContractAddress) -> u256;
   fn allowance(self: @TState, owner: ContractAddress, spender: ContractAddress) -> u256;
   fn transfer(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
   fn transfer_from(ref self: TState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
}

#[starknet::interface]
 pub trait IReentrancyProbe<TState> {
    fn attempt_reentry(ref self: TState, account: ContractAddress, token: ContractAddress, recipient: ContractAddress,
    amount: u256, nonce: felt252, execute_after: u64, execute_before: u64, signature: Array<felt252>);

    fn was_reentry_rejected(self: @TState) -> bool;
}

 #[starknet::contract]
 pub mod MockERC20 {
    use starknet::{get_caller_address};
    use super::{ContractAddress};
    use starknet::storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry};

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
        allowances: Map<ContractAddress, Map<ContractAddress, u256>>
    }

    #[constructor]
    fn constructor(ref self: ContractState){}

    #[abi(embed_v0)] 
    impl MockERC20 of super::IMockERC20<ContractState> {

        fn mint(ref self: ContractState, to: ContractAddress, amount: u256){
            let current_balance = self.balances.entry(to).read();
            self.balances.entry(to).write(current_balance + amount);
        }

        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256){
            let caller = get_caller_address();
            assert(amount > 0, 'amount must be over zero');
            self.allowances.entry(caller).entry(spender).write(amount);
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> u256{
            self.balances.entry(account).read()
        }

        fn allowance(self: @ContractState, owner: ContractAddress, spender: ContractAddress) -> u256{
             self.allowances.entry(owner).entry(spender).read()
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
             let caller = get_caller_address();
            let caller_balance = self.balances.entry(caller).read();
            assert(caller_balance >= amount, 'Insufficient funds');
            assert(amount > 0, 'amount must be over zero');
            let new_balance = caller_balance - amount;
            self.balances.entry(caller).write(new_balance);
            let recipient_balance = self.balances.entry(recipient).read() + amount;
            self.balances.entry(recipient).write(recipient_balance);
            return true;
        }

        fn transfer_from(ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool {
            let caller = get_caller_address();
            let allowed = self.allowances.entry(sender).entry(caller).read();
            assert(allowed >= amount, 'Not enough allowance');
            
            let sender_balance = self.balances.entry(sender).read();
            assert(sender_balance >= amount, 'Insufficient funds');
            
            self.balances.entry(sender).write(sender_balance - amount);
            self.balances.entry(recipient).write(self.balances.entry(recipient).read() + amount);
            self.allowances.entry(sender).entry(caller).write(allowed - amount);
            
            return true;
        }
    }
}

#[starknet::contract]
pub mod ReentrancyProbe{
    use crate::OutsideExecution;
    use super::{ContractAddress};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::account::Call as StarknetCall;
    use crate::IOutsideExecutionV2SafeDispatcher;
    use crate::IOutsideExecutionV2SafeDispatcherTrait;
    

#[storage]
    struct Storage {
       reentry_rejected: bool,
    }

#[constructor]
    fn constructor(ref self: ContractState){}

#[abi(embed_v0)] 
    impl ImplReentrancyProbe of super::IReentrancyProbe<ContractState>{

#[feature("safe_dispatcher")]
        fn attempt_reentry(ref self: ContractState, account: ContractAddress, token: ContractAddress, recipient: ContractAddress,
            amount: u256, nonce: felt252, execute_after: u64, execute_before: u64, signature: Array<felt252>){
            let any_caller: ContractAddress = 0x414e595f43414c4c4552;
            let new_recipient: felt252 = recipient.into();
            let new_amount_low: felt252 = amount.low.into();
            let new_amount_high: felt252 = amount.high.into();

            let call = StarknetCall {to: token, selector: selector!("transfer"), calldata: array![new_recipient, new_amount_low, new_amount_high].span()};
            let outside_execution = OutsideExecution { caller: any_caller, nonce: nonce, execute_after: execute_after, execute_before: execute_before, calls: array![call].span()}; 

            let safe_dispatcher = IOutsideExecutionV2SafeDispatcher { contract_address: account };
            let res = safe_dispatcher.execute_from_outside_v2(outside_execution, signature.span());
            match res{
                Result::Ok(_) => {
                    self.reentry_rejected.write(false);
                },
                Result::Err(_) => {
                    self.reentry_rejected.write(true);

                }
            }
        }

        fn was_reentry_rejected(self: @ContractState) -> bool{
            self.reentry_rejected.read()
        }
    }
}