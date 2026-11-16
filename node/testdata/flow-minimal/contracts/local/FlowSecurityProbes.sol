// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Local adversarial fixtures only. These do not replace the upstream Flow
// Factory, Pair, Router, LQCTestToken or MockWBNB.
interface IWrappedFlowTest {
    function deposit() external payable;
    function withdraw(uint256) external;
}
contract FlowWithdrawalProbe {
    IWrappedFlowTest public immutable wrapper;
    bool public attempted;
    bool public blocked;
    uint256 private amount;
    constructor(address target) { wrapper=IWrappedFlowTest(target); }
    function exercise() external payable {
        amount=msg.value;
        wrapper.deposit{value:msg.value}();
        wrapper.withdraw(msg.value);
    }
    receive() external payable {
        if (!attempted) {
            attempted=true;
            (bool ok,)=address(wrapper).call(abi.encodeCall(IWrappedFlowTest.withdraw,(amount)));
            blocked=!ok;
        }
    }
}

contract FlowCallbackToken {
    string public constant name="Local adversarial Flow token";
    string public constant symbol="ATTACK-TEST";
    uint8 public constant decimals=18;
    uint256 public totalSupply;
    mapping(address=>uint256) public balanceOf;
    mapping(address=>mapping(address=>uint256)) public allowance;
    address public target;
    bool public attempted;
    bool public blocked;
    bytes4 public rejection;
    event Transfer(address indexed from,address indexed to,uint256 amount);
    event Approval(address indexed owner,address indexed spender,uint256 amount);
    function mint(address to,uint256 amount) external {
        totalSupply+=amount;balanceOf[to]+=amount;emit Transfer(address(0),to,amount);
    }
    function arm(address pair) external {target=pair;}
    function approve(address to,uint256 amount) external returns(bool) {
        allowance[msg.sender][to]=amount;emit Approval(msg.sender,to,amount);return true;
    }
    function transfer(address to,uint256 amount) external returns(bool) {
        _transfer(msg.sender,to,amount);
        if(msg.sender==target&&!attempted) {
            attempted=true;
            (bool ok,bytes memory reason)=target.call(abi.encodeWithSignature("sync()"));
            blocked=!ok;
            if(reason.length>=4) {rejection=bytes4(reason);}
        }
        return true;
    }
    function transferFrom(address from,address to,uint256 amount) external returns(bool) {
        allowance[from][msg.sender]-=amount;_transfer(from,to,amount);return true;
    }
    function _transfer(address from,address to,uint256 amount) private {
        balanceOf[from]-=amount;balanceOf[to]+=amount;emit Transfer(from,to,amount);
    }
}
