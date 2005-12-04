/*------------------------------------------------------------------------
 . smc91111.h - macros for the LAN91C111 Ethernet Driver
 .
 . Copyright (C) 2001 Standard Microsystems Corporation (SMSC)
 .       Developed by Simple Network Magic Corporation (SNMC)
 . Copyright (C) 1996 by Erik Stahlman (ES)
 .
 . This program is free software; you can redistribute it and/or modify
 . it under the terms of the GNU General Public License as published by
 . the Free Software Foundation; either version 2 of the License, or
 . (at your option) any later version.
 .
 . This program is distributed in the hope that it will be useful,
 . but WITHOUT ANY WARRANTY; without even the implied warranty of
 . MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 . GNU General Public License for more details.
 .
 . You should have received a copy of the GNU General Public License
 . along with this program; if not, write to the Free Software
 . Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 .
 . This file contains register information and access macros for 
 . the LAN91C111 single chip ethernet controller.  It is a modified
 . version of the smc9194.h file.
 . 
 . Information contained in this file was obtained from the LAN91C111
 . manual from SMC.  To get a copy, if you really want one, you can find 
 . information under www.smsc.com.
 . 
 . Authors
 . 	Erik Stahlman				( erik@vt.edu )
 .	Daris A Nevil				( dnevil@snmc.com )
 .
 . History
 . 03/16/01		Daris A Nevil	Modified for use with LAN91C111 device
 .
 ---------------------------------------------------------------------------*/
#ifndef _SMC91111_H_
#define _SMC91111_H_

/* I want some simple types */

typedef unsigned char			byte;
typedef unsigned short			word;
typedef unsigned long int 		dword;


/* Because of bank switching, the LAN91xxx uses only 16 I/O ports */

#define SMC_IO_EXTENT	16


/*---------------------------------------------------------------
 .  
 . A description of the SMSC registers is probably in order here,
 . although for details, the SMC datasheet is invaluable.  
 . 
 . Basically, the chip has 4 banks of registers ( 0 to 3 ), which
 . are accessed by writing a number into the BANK_SELECT register
 . ( I also use a SMC_SELECT_BANK macro for this ).
 . 
 . The banks are configured so that for most purposes, bank 2 is all
 . that is needed for simple run time tasks.  
 -----------------------------------------------------------------------*/

/*
 . Bank Select Register: 
 .
 .		yyyy yyyy 0000 00xx  
 .		xx 		= bank number
 .		yyyy yyyy	= 0x33, for identification purposes.
*/
#define	BANK_SELECT		14

// Transmit Control Register
/* BANK 0  */
#define	TCR_REG 	0x0000 	// transmit control register 
#define TCR_ENABLE	0x0001	// When 1 we can transmit
#define TCR_LOOP	0x0002	// Controls output pin LBK
#define TCR_FORCOL	0x0004	// When 1 will force a collision
#define TCR_PAD_EN	0x0080	// When 1 will pad tx frames < 64 bytes w/0
#define TCR_NOCRC	0x0100	// When 1 will not append CRC to tx frames
#define TCR_MON_CSN	0x0400	// When 1 tx monitors carrier
#define TCR_FDUPLX    	0x0800  // When 1 enables full duplex operation
#define TCR_STP_SQET	0x1000	// When 1 stops tx if Signal Quality Error
#define	TCR_EPH_LOOP	0x2000	// When 1 enables EPH block loopback
#define	TCR_SWFDUP	0x8000	// When 1 enables Switched Full Duplex mode

#define	TCR_CLEAR	0	/* do NOTHING */
/* the default settings for the TCR register : */ 
/* QUESTION: do I want to enable padding of short packets ? */
#define	TCR_DEFAULT  	TCR_ENABLE 


// EPH Status Register
/* BANK 0  */
#define EPH_STATUS_REG	0x0002
#define ES_TX_SUC	0x0001	// Last TX was successful
#define ES_SNGL_COL	0x0002	// Single collision detected for last tx
#define ES_MUL_COL	0x0004	// Multiple collisions detected for last tx
#define ES_LTX_MULT	0x0008	// Last tx was a multicast
#define ES_16COL	0x0010	// 16 Collisions Reached
#define ES_SQET		0x0020	// Signal Quality Error Test
#define ES_LTXBRD	0x0040	// Last tx was a broadcast
#define ES_TXDEFR	0x0080	// Transmit Deferred
#define ES_LATCOL	0x0200	// Late collision detected on last tx
#define ES_LOSTCARR	0x0400	// Lost Carrier Sense
#define ES_EXC_DEF	0x0800	// Excessive Deferral
#define ES_CTR_ROL	0x1000	// Counter Roll Over indication
#define ES_LINK_OK	0x4000	// Driven by inverted value of nLNK pin
#define ES_TXUNRN	0x8000	// Tx Underrun


// Receive Control Register
/* BANK 0  */
#define	RCR_REG		0x0004
#define	RCR_RX_ABORT	0x0001	// Set if a rx frame was aborted
#define	RCR_PRMS	0x0002	// Enable promiscuous mode
#define	RCR_ALMUL	0x0004	// When set accepts all multicast frames
#define RCR_RXEN	0x0100	// IFF this is set, we can receive packets
#define	RCR_STRIP_CRC	0x0200	// When set strips CRC from rx packets
#define	RCR_ABORT_ENB	0x0200	// When set will abort rx on collision 
#define	RCR_FILT_CAR	0x0400	// When set filters leading 12 bit s of carrier
#define RCR_SOFTRST	0x8000 	// resets the chip

/* the normal settings for the RCR register : */
#define	RCR_DEFAULT	(RCR_STRIP_CRC | RCR_RXEN)
#define RCR_CLEAR	0x0	// set it to a base state

// Counter Register
/* BANK 0  */
#define	COUNTER_REG	0x0006

// Memory Information Register
/* BANK 0  */
#define	MIR_REG		0x0008

// Receive/Phy Control Register
/* BANK 0  */
#define	RPC_REG		0x000A
#define	RPC_SPEED	0x2000	// When 1 PHY is in 100Mbps mode.
#define	RPC_DPLX	0x1000	// When 1 PHY is in Full-Duplex Mode
#define	RPC_ANEG	0x0800	// When 1 PHY is in Auto-Negotiate Mode
#define	RPC_LSXA_SHFT	5	// Bits to shift LS2A,LS1A,LS0A to lsb
#define	RPC_LSXB_SHFT	2	// Bits to get LS2B,LS1B,LS0B to lsb
#define RPC_LED_100_10	(0x00)	// LED = 100Mbps OR's with 10Mbps link detect
#define RPC_LED_RES	(0x01)	// LED = Reserved
#define RPC_LED_10	(0x02)	// LED = 10Mbps link detect
#define RPC_LED_FD	(0x03)	// LED = Full Duplex Mode
#define RPC_LED_TX_RX	(0x04)	// LED = TX or RX packet occurred
#define RPC_LED_100	(0x05)	// LED = 100Mbps link dectect
#define RPC_LED_TX	(0x06)	// LED = TX packet occurred
#define RPC_LED_RX	(0x07)	// LED = RX packet occurred
#define RPC_DEFAULT (RPC_ANEG | (RPC_LED_100 << RPC_LSXA_SHFT) | (RPC_LED_FD << RPC_LSXB_SHFT) | RPC_SPEED | RPC_DPLX)

/* Bank 0 0x000C is reserved */

// Bank Select Register
/* All Banks */
#define BSR_REG	0x000E


// Configuration Reg
/* BANK 1 */
#define CONFIG_REG	0x0000
#define CONFIG_EXT_PHY	0x0200	// 1=external MII, 0=internal Phy
#define CONFIG_GPCNTRL	0x0400	// Inverse value drives pin nCNTRL
#define CONFIG_NO_WAIT	0x1000	// When 1 no extra wait states on ISA bus
#define CONFIG_EPH_POWER_EN 0x8000 // When 0 EPH is placed into low power mode.

// Default is powered-up, Internal Phy, Wait States, and pin nCNTRL=low
#define CONFIG_DEFAULT	(CONFIG_EPH_POWER_EN)


// Base Address Register
/* BANK 1 */
#define	BASE_REG	0x0002


// Individual Address Registers
/* BANK 1 */
#define	ADDR0_REG	0x0004
#define	ADDR1_REG	0x0006
#define	ADDR2_REG	0x0008


// General Purpose Register
/* BANK 1 */
#define	GP_REG		0x000A


// Control Register
/* BANK 1 */
#define	CTL_REG		0x000C
#define CTL_RCV_BAD	0x4000 // When 1 bad CRC packets are received
#define CTL_AUTO_RELEASE 0x0800 // When 1 tx pages are released automatically
#define	CTL_LE_ENABLE	0x0080 // When 1 enables Link Error interrupt
#define	CTL_CR_ENABLE	0x0040 // When 1 enables Counter Rollover interrupt
#define	CTL_TE_ENABLE	0x0020 // When 1 enables Transmit Error interrupt
#define	CTL_EEPROM_SELECT 0x0004 // Controls EEPROM reload & store
#define	CTL_RELOAD	0x0002 // When set reads EEPROM into registers
#define	CTL_STORE	0x0001 // When set stores registers into EEPROM


// MMU Command Register
/* BANK 2 */
#define MMU_CMD_REG	0x0000
#define MC_BUSY		1	// When 1 the last release has not completed
#define MC_NOP		(0<<5)	// No Op
#define	MC_ALLOC	(1<<5) 	// OR with number of 256 byte packets
#define	MC_RESET	(2<<5)	// Reset MMU to initial state
#define	MC_REMOVE	(3<<5) 	// Remove the current rx packet
#define MC_RELEASE  	(4<<5) 	// Remove and release the current rx packet
#define MC_FREEPKT  	(5<<5) 	// Release packet in PNR register
#define MC_ENQUEUE	(6<<5)	// Enqueue the packet for transmit
#define MC_RSTTXFIFO	(7<<5)	// Reset the TX FIFOs


// Packet Number Register
/* BANK 2 */
#define	PN_REG		0x0002


// Allocation Result Register
/* BANK 2 */
#define	AR_REG		0x0003
#define AR_FAILED	0x80	// Alocation Failed


// RX FIFO Ports Register
/* BANK 2 */
#define RXFIFO_REG	0x0004	// Must be read as a word
#define RXFIFO_REMPTY	0x8000	// RX FIFO Empty


// TX FIFO Ports Register
/* BANK 2 */
#define TXFIFO_REG	RXFIFO_REG	// Must be read as a word
#define TXFIFO_TEMPTY	0x80	// TX FIFO Empty


// Pointer Register
/* BANK 2 */
#define PTR_REG		0x0006
#define	PTR_RCV		0x8000 // 1=Receive area, 0=Transmit area
#define	PTR_AUTOINC 	0x4000 // Auto increment the pointer on each access
#define PTR_READ	0x2000 // When 1 the operation is a read


// Data Register
/* BANK 2 */
#define	DATA_REG	0x0008


// Interrupt Status/Acknowledge Register
/* BANK 2 */
#define	INT_REG		0x000C


// Interrupt Mask Register
/* BANK 2 */
#define IM_REG		0x000D
#define	IM_MDINT	0x80 // PHY MI Register 18 Interrupt
#define	IM_ERCV_INT	0x40 // Early Receive Interrupt
#define	IM_EPH_INT	0x20 // Set by Etheret Protocol Handler section
#define	IM_RX_OVRN_INT	0x10 // Set by Receiver Overruns
#define	IM_ALLOC_INT	0x08 // Set when allocation request is completed
#define	IM_TX_EMPTY_INT	0x04 // Set if the TX FIFO goes empty
#define	IM_TX_INT	0x02 // Transmit Interrrupt
#define IM_RCV_INT	0x01 // Receive Interrupt


// Multicast Table Registers
/* BANK 3 */
#define	MCAST_REG1	0x0000
#define	MCAST_REG2	0x0002
#define	MCAST_REG3	0x0004
#define	MCAST_REG4	0x0006


// Management Interface Register (MII)
/* BANK 3 */
#define	MII_REG		0x0008
#define MII_MSK_CRS100	0x4000 // Disables CRS100 detection during tx half dup
#define MII_MDOE	0x0008 // MII Output Enable
#define MII_MCLK	0x0004 // MII Clock, pin MDCLK
#define MII_MDI		0x0002 // MII Input, pin MDI
#define MII_MDO		0x0001 // MII Output, pin MDO


// Revision Register
/* BANK 3 */
#define	REV_REG		0x000A /* ( hi: chip id   low: rev # ) */


// Early RCV Register
/* BANK 3 */
/* this is NOT on SMC9192 */
#define	ERCV_REG	0x000C
#define ERCV_RCV_DISCRD	0x0080 // When 1 discards a packet being received
#define ERCV_THRESHOLD	0x001F // ERCV Threshold Mask

// External Register
/* BANK 7 */
#define	EXT_REG		0x0000


#define CHIP_9192	3
#define CHIP_9194	4
#define CHIP_9195	5
#define CHIP_9196	6
#define CHIP_91100	7
#define CHIP_91100FD	8
#define CHIP_91111FD	9

static const char * chip_ids[ 15 ] =  { 
	NULL, NULL, NULL, 
	/* 3 */ "SMC91C90/91C92",
	/* 4 */ "SMC91C94",
	/* 5 */ "SMC91C95",
	/* 6 */ "SMC91C96",
	/* 7 */ "SMC91C100", 
	/* 8 */ "SMC91C100FD", 
	/* 9 */ "SMC91C11xFD", 
	NULL, NULL, 
	NULL, NULL, NULL};  

/* 
 . Transmit status bits 
*/
#define TS_SUCCESS 0x0001
#define TS_LOSTCAR 0x0400
#define TS_LATCOL  0x0200
#define TS_16COL   0x0010

/*
 . Receive status bits
*/
#define RS_ALGNERR	0x8000
#define RS_BRODCAST	0x4000
#define RS_BADCRC	0x2000
#define RS_ODDFRAME	0x1000	// bug: the LAN91C111 never sets this on receive
#define RS_TOOLONG	0x0800
#define RS_TOOSHORT	0x0400
#define RS_MULTICAST	0x0001
#define RS_ERRORS	(RS_ALGNERR | RS_BADCRC | RS_TOOLONG | RS_TOOSHORT) 


// PHY Types
enum {
	PHY_LAN83C183 = 1,	// LAN91C111 Internal PHY
	PHY_LAN83C180
};


// PHY Register Addresses (LAN91C111 Internal PHY)

// PHY Control Register
#define PHY_CNTL_REG		0x00
#define PHY_CNTL_RST		0x8000	// 1=PHY Reset
#define PHY_CNTL_LPBK		0x4000	// 1=PHY Loopback
#define PHY_CNTL_SPEED		0x2000	// 1=100Mbps, 0=10Mpbs
#define PHY_CNTL_ANEG_EN	0x1000 // 1=Enable Auto negotiation
#define PHY_CNTL_PDN		0x0800	// 1=PHY Power Down mode
#define PHY_CNTL_MII_DIS	0x0400	// 1=MII 4 bit interface disabled
#define PHY_CNTL_ANEG_RST	0x0200 // 1=Reset Auto negotiate
#define PHY_CNTL_DPLX		0x0100	// 1=Full Duplex, 0=Half Duplex
#define PHY_CNTL_COLTST		0x0080	// 1= MII Colision Test

// PHY Status Register
#define PHY_STAT_REG		0x01
#define PHY_STAT_CAP_T4		0x8000	// 1=100Base-T4 capable
#define PHY_STAT_CAP_TXF	0x4000	// 1=100Base-X full duplex capable
#define PHY_STAT_CAP_TXH	0x2000	// 1=100Base-X half duplex capable
#define PHY_STAT_CAP_TF		0x1000	// 1=10Mbps full duplex capable
#define PHY_STAT_CAP_TH		0x0800	// 1=10Mbps half duplex capable
#define PHY_STAT_CAP_SUPR	0x0040	// 1=recv mgmt frames with not preamble
#define PHY_STAT_ANEG_ACK	0x0020	// 1=ANEG has completed
#define PHY_STAT_REM_FLT	0x0010	// 1=Remote Fault detected
#define PHY_STAT_CAP_ANEG	0x0008	// 1=Auto negotiate capable
#define PHY_STAT_LINK		0x0004	// 1=valid link
#define PHY_STAT_JAB		0x0002	// 1=10Mbps jabber condition
#define PHY_STAT_EXREG		0x0001	// 1=extended registers implemented

// PHY Identifier Registers
#define PHY_ID1_REG		0x02	// PHY Identifier 1
#define PHY_ID2_REG		0x03	// PHY Identifier 2

// PHY Auto-Negotiation Advertisement Register
#define PHY_AD_REG		0x04
#define PHY_AD_NP		0x8000	// 1=PHY requests exchange of Next Page
#define PHY_AD_ACK		0x4000	// 1=got link code word from remote
#define PHY_AD_RF		0x2000	// 1=advertise remote fault
#define PHY_AD_T4		0x0200	// 1=PHY is capable of 100Base-T4
#define PHY_AD_TX_FDX		0x0100	// 1=PHY is capable of 100Base-TX FDPLX
#define PHY_AD_TX_HDX		0x0080	// 1=PHY is capable of 100Base-TX HDPLX
#define PHY_AD_10_FDX		0x0040	// 1=PHY is capable of 10Base-T FDPLX
#define PHY_AD_10_HDX		0x0020	// 1=PHY is capable of 10Base-T HDPLX
#define PHY_AD_CSMA		0x0001	// 1=PHY is capable of 802.3 CMSA

// PHY Auto-negotiation Remote End Capability Register
#define PHY_RMT_REG		0x05
// Uses same bit definitions as PHY_AD_REG

// PHY Configuration Register 1
#define PHY_CFG1_REG		0x10
#define PHY_CFG1_LNKDIS		0x8000	// 1=Rx Link Detect Function disabled
#define PHY_CFG1_XMTDIS		0x4000	// 1=TP Transmitter Disabled
#define PHY_CFG1_XMTPDN		0x2000	// 1=TP Transmitter Powered Down
#define PHY_CFG1_BYPSCR		0x0400	// 1=Bypass scrambler/descrambler
#define PHY_CFG1_UNSCDS		0x0200	// 1=Unscramble Idle Reception Disable
#define PHY_CFG1_EQLZR		0x0100	// 1=Rx Equalizer Disabled
#define PHY_CFG1_CABLE		0x0080	// 1=STP(150ohm), 0=UTP(100ohm)
#define PHY_CFG1_RLVL0		0x0040	// 1=Rx Squelch level reduced by 4.5db
#define PHY_CFG1_TLVL_SHIFT	2	// Transmit Output Level Adjust
#define PHY_CFG1_TLVL_MASK	0x003C
#define PHY_CFG1_TRF_MASK	0x0003	// Transmitter Rise/Fall time


// PHY Configuration Register 2
#define PHY_CFG2_REG		0x11
#define PHY_CFG2_APOLDIS	0x0020	// 1=Auto Polarity Correction disabled
#define PHY_CFG2_JABDIS		0x0010	// 1=Jabber disabled
#define PHY_CFG2_MREG		0x0008	// 1=Multiple register access (MII mgt)
#define PHY_CFG2_INTMDIO	0x0004	// 1=Interrupt signaled with MDIO pulseo

// PHY Status Output (and Interrupt status) Register
#define PHY_INT_REG		0x12	// Status Output (Interrupt Status)
#define PHY_INT_INT		0x8000	// 1=bits have changed since last read
#define	PHY_INT_LNKFAIL		0x4000	// 1=Link Not detected
#define PHY_INT_LOSSSYNC	0x2000	// 1=Descrambler has lost sync
#define PHY_INT_CWRD		0x1000	// 1=Invalid 4B5B code detected on rx
#define PHY_INT_SSD		0x0800	// 1=No Start Of Stream detected on rx
#define PHY_INT_ESD		0x0400	// 1=No End Of Stream detected on rx
#define PHY_INT_RPOL		0x0200	// 1=Reverse Polarity detected
#define PHY_INT_JAB		0x0100	// 1=Jabber detected
#define PHY_INT_SPDDET		0x0080	// 1=100Base-TX mode, 0=10Base-T mode
#define PHY_INT_DPLXDET		0x0040	// 1=Device in Full Duplex

// PHY Interrupt/Status Mask Register
#define PHY_MASK_REG		0x13	// Interrupt Mask
// Uses the same bit definitions as PHY_INT_REG



/*-------------------------------------------------------------------------
 .  I define some macros to make it easier to do somewhat common
 . or slightly complicated, repeated tasks. 
 --------------------------------------------------------------------------*/

/* select a register bank, 0 to 3  */

#define SMC_SELECT_BANK(x)  { outw( x, ioaddr + BANK_SELECT ); } 

/* this enables an interrupt in the interrupt mask register */
#define SMC_ENABLE_INT(x) {\
		unsigned char mask;\
		SMC_SELECT_BANK(2);\
		mask = inb( ioaddr + IM_REG );\
		mask |= (x);\
		outb( mask, ioaddr + IM_REG ); \
}

/* this disables an interrupt from the interrupt mask register */

#define SMC_DISABLE_INT(x) {\
		unsigned char mask;\
		SMC_SELECT_BANK(2);\
		mask = inb( ioaddr + IM_REG );\
		mask &= ~(x);\
		outb( mask, ioaddr + IM_REG ); \
}

/*----------------------------------------------------------------------
 . Define the interrupts that I want to receive from the card
 . 
 . I want: 
 .  IM_EPH_INT, for nasty errors
 .  IM_RCV_INT, for happy received packets
 .  IM_RX_OVRN_INT, because I have to kick the receiver
 .  IM_MDINT, for PHY Register 18 Status Changes
 --------------------------------------------------------------------------*/
#define SMC_INTERRUPT_MASK   (IM_EPH_INT | IM_RX_OVRN_INT | IM_RCV_INT | \
	IM_MDINT) 


#ifdef CONFIG_SYSCTL


/*
 * Declarations for the sysctl interface, which allows users the ability to
 * control the finer aspects of the LAN91C111 chip.  Since the smc
 * module currently registers its sysctl table dynamically, the sysctl path
 * for module FOO is /proc/sys/dev/ethX/FOO
 */
#define CTL_SMC         (CTL_BUS+1389)      // arbitrary and hopefully unused

enum {
	CTL_SMC_INFO = 1,	// Sysctl files information
	CTL_SMC_SWVER,		// Driver Software Version Info
	CTL_SMC_SWFDUP,		// Switched Full Duplex Mode
	CTL_SMC_EPHLOOP,	// EPH Block Internal Loopback
	CTL_SMC_MIIOP,		// MII Operation
	CTL_SMC_AUTONEG,	// Auto-negotiate Mode
	CTL_SMC_RFDUPLX,	// Request Full Duplex Mode
	CTL_SMC_RSPEED,		// Request Speed Selection
	CTL_SMC_AFDUPLX,	// Actual Full Duplex Mode
	CTL_SMC_ASPEED,		// Actual Speed Selection
	CTL_SMC_LNKFAIL,	// Link Failed
	CTL_SMC_FORCOL,		// Force a Collision
	CTL_SMC_FILTCAR,	// Filter Carrier
	CTL_SMC_FREEMEM,	// Free Buffer Memory
	CTL_SMC_TOTMEM,		// Total Buffer Memory
	CTL_SMC_LEDA,		// Output of LED-A
	CTL_SMC_LEDB,		// Output of LED-B
	CTL_SMC_CHIPREV,	// LAN91C111 Chip Revision ID
#ifdef SMC_DEBUG
	// Register access for debugging
	CTL_SMC_REG_BSR,	// Bank Select
	CTL_SMC_REG_TCR,	// Transmit Control
	CTL_SMC_REG_ESR,	// EPH Status
	CTL_SMC_REG_RCR,	// Receive Control
	CTL_SMC_REG_CTRR,	// Counter
	CTL_SMC_REG_MIR,	// Memory Information
	CTL_SMC_REG_RPCR,	// Receive/Phy Control
	CTL_SMC_REG_CFGR,	// Configuration
	CTL_SMC_REG_BAR,	// Base Address
	CTL_SMC_REG_IAR0,	// Individual Address 0
	CTL_SMC_REG_IAR1,	// Individual Address 1 
	CTL_SMC_REG_IAR2,	// Individual Address 2
	CTL_SMC_REG_GPR,	// General Purpose
	CTL_SMC_REG_CTLR,	// Control
	CTL_SMC_REG_MCR,	// MMU Command
	CTL_SMC_REG_PNR,	// Packet Number
	CTL_SMC_REG_FPR,	// FIFO Ports
	CTL_SMC_REG_PTR,	// Pointer
	CTL_SMC_REG_DR,		// Data 
	CTL_SMC_REG_ISR,	// Interrupt Status
	CTL_SMC_REG_MTR1,	// Multicast Table Entry 1
	CTL_SMC_REG_MTR2,	// Multicast Table Entry 2
	CTL_SMC_REG_MTR3,	// Multicast Table Entry 3
	CTL_SMC_REG_MTR4,	// Multicast Table Entry 4
	CTL_SMC_REG_MIIR,	// Management Interface
	CTL_SMC_REG_REVR,	// Revision
	CTL_SMC_REG_ERCVR,	// Early RCV
	CTL_SMC_REG_EXTR,	// External
	CTL_SMC_PHY_CTRL,	// PHY Control
	CTL_SMC_PHY_STAT,	// PHY Status
	CTL_SMC_PHY_ID1,	// PHY ID1
	CTL_SMC_PHY_ID2,	// PHY ID2
	CTL_SMC_PHY_ADC,	// PHY Advertise Capability
	CTL_SMC_PHY_REMC,	// PHY Advertise Capability
	CTL_SMC_PHY_CFG1,	// PHY Configuration 1
	CTL_SMC_PHY_CFG2,	// PHY Configuration 2
	CTL_SMC_PHY_INT,	// PHY Interrupt/Status Output
	CTL_SMC_PHY_MASK,	// PHY Interrupt/Status Mask
#endif
	// ---------------------------------------------------
	CTL_SMC_LAST_ENTRY	// Add new entries above the line
};

#endif // CONFIG_SYSCTL
 
#endif  /* _SMC_91111_H_ */


