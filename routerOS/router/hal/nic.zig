/// Build-time NIC driver selector.
/// Compile with -Dnic=x550 to use the x550 driver, default is e1000.
const build_options = @import("build_options");

const driver = if (build_options.use_x550) @import("x550.zig") else @import("e1000.zig");

// Re-export all public declarations from the selected driver
pub const RxDesc = driver.RxDesc;
pub const TxDesc = driver.TxDesc;
pub const RxResult = driver.RxResult;
pub const InitParams = driver.InitParams;
pub const NUM_RX_DESC = driver.NUM_RX_DESC;
pub const NUM_TX_DESC = driver.NUM_TX_DESC;
pub const PACKET_BUF_SIZE = driver.PACKET_BUF_SIZE;
pub const RX_DESC_DD = driver.RX_DESC_DD;
pub const TX_DESC_CMD_EOP = driver.TX_DESC_CMD_EOP;
pub const TX_DESC_CMD_IFCS = driver.TX_DESC_CMD_IFCS;
pub const TX_DESC_CMD_RS = driver.TX_DESC_CMD_RS;
pub const TX_DESC_STA_DD = driver.TX_DESC_STA_DD;

pub const readReg = driver.readReg;
pub const writeReg = driver.writeReg;
pub const readMac = driver.readMac;
pub const init = driver.init;
pub const rxPoll = driver.rxPoll;
pub const rxReturn = driver.rxReturn;
pub const txSendAddr = driver.txSendAddr;
pub const txSendCopy = driver.txSendCopy;
pub const txDone = driver.txDone;
pub const clearIrq = driver.clearIrq;
pub const linkUp = driver.linkUp;
