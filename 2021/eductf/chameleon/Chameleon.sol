pragma solidity ^0.5.17;

contract Chameleon {
    uint randomNumber = 0;
    bool public sendFlag = false;
    
    function HideAndSeek() public {
        bool success;
        (success,) = msg.sender.delegatecall(abi.encodeWithSignature(""));
        require(!success);
        (success,) = msg.sender.delegatecall(abi.encodeWithSignature(""));
        require(success);
    }
}
