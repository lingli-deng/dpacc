/* An otocol driver using virtio.
 *
 * Copyright 2015 Freescale Semiconductor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
/*
 * @file virtio_flow_api.h
 * 
 * @brief Contains  g_flow_api function declarations & definitions
 *
 * @addtogroup VIRTIO_FLOW
 * @{
*/

#ifndef _VIRTIO_FLOW_API_H
#define _VIRTIO_FLOW_API_H

/* To be added into virtio header file */
/*! Macros */
/*! Virtio Flow Vendor ID and Device ID  TBD - Defining IDs */
#define VIRTIO_FLOW_VENDOR_ID 0xXXXX
#define VIRTIO_FLOW_DEVICE_ID 0xYYYY

/*! Maximum version length. The version will be of the form major:minor; 
    The Most significant 8 bits will indicate the major number, and remaining 24 bits will indicate the minor number */
#define G_FLOW_MAX_VERSION_LENGTH	32


/*! Success and Failure macros */
#define G_FLOW_FAILURE -1
#define G_FLOW_SUCCESS  0

/*! Flow Device name maximum size */
#define G_FLOW_VIRTUAL_ACCEL_NAME_SIZE	16	

/*! Flow Device Port name maximum size */
#define G_FLOW_DP_PORT_NAME_SIZE	16	

/*! Flow Device handle size */
#define G_FLOW_HANDLE_SIZE	8

/*! Datapath maximum table name length possible */
#define G_FLOW_MAX_TABLE_NAME_LEN 32


/*! Enumerations */

/* Enums of Port status change event types */
enum g_flow_dp_port_status_event {
        G_FLOW_DP_PORT_ADD = 0, /**< Port added to datapath */
        G_FLOW_DP_PORT_MOD = 1, /**< Earlier added Port to datapath modified */
        G_FLOW_DP_PORT_DEL = 2, /**< Earlier added Port to datapath deleted */
};

/*! Get Available flow devices inArgs */
struct g_flow_avail_devices_get_inargs {
	uint32_t num_devices; /**< Number of devices to get */
	char *last_device_read; 
	/**< NULL if this is the first time this call is invoked;
          Subsequent calls will have a valid value here */											  
};

/*! Flow Device information */ 
struct g_flow_device_info {
	char flow_virtual_accel_name[G_FLOW_VIRTUAL_ACCEL_NAME_SIZE]; /**< Device name  of flow accclerator*/
        uint64_t  datapath_id;/**< ID of the datapath to which device associcated */
};

/*! Flow avaialble devices get outArgs */
struct g_flow_avail_devices_get_outargs {
	uint32_t num_devices; /**< number of devices to get */
	struct g_flow_device_info *dev_info; 						
	/**< Array of pointers, where each points to
	    device specific information */
	char *last_device_read; 
	/**< Send a value that the application can use and
	  * invoke for the next set of devices */
	bool b_more_devices;
	/**< Set if more devices are available */
};

/*! Handles */
struct g_flow_handle {
	u8 handle[G_FLOW_HANDLE_SIZE]; /**< Accelerator handle */
};

/*! Accelerator Open inArgs */
struct g_flow_open_datapath_inargs {
	uint16_t pci_vendor_id; /**< PCI Vendor ID 0xXXXX */
	uint16_t device_id;     /**< Device Id for Flow */
	char *flow_virtual_accel_name;        /**< Accelerator name */
};

/*! Accelerator Open OutArgs */
struct g_flow_open_datapath_outargs {
        struct g_flow_handle *handle; /** handle */
};

/*! Datapath Port Info*/
struct g_flow_dp_port_info {
     uint32_t id; /**< ID of the port assigned to datapath */
     char name[G_FLOW_DP_PORT_NAME_SIZE]; /**< Name of port assigned to datapath */
};

/*! Get Port details of given datapath inArgs */
struct g_flow_dp_ports_get_inargs {
	uint32_t num_ports; /**< Number of ports to get */
	char *last_port_read; 
	/**< NULL if this is the first time this call is invoked;
          Subsequent calls will have a valid value here */											  
};

/*! Flow tables information get outArgs */
struct g_flow_dp_ports_get_outargs {
	uint32_t num_ports; /**< number of ports to get */
	struct g_flow_dp_port_info *port_info; 						
	/**< Array of pointers, where each points to
	    port specific information */
	char *last_port_read; 
	/**< Send a value that the application can use and
	  * invoke for the next set of ports */
	bool b_more_ports;
	/**< Set if more ports are available */
};

/*! Callback function prototype that application can provide to receive datapath associated event,
    event indicating that datpath is exposed to VNF */
typedef void (*g_flow_cbk_dp_associated_fn) (
        struct g_flow_handle *handle,
        uint64_t datapath_id,
        void *cbk_arg1,
        void *cbk_arg2);

/*! Port status change event info*/
struct g_flow_dp_port_status {
      enum g_flow_dp_port_status_event event_type; /**< Type of port status change event */
      struct g_flow_dp_port_info port_info; /**< Details of port which changed status */
};

/*! Callabck function prototype that application to receive event when there is change in the port status*/ 
typedef void (*g_flow_cbk_dp_port_status_change_fn) (
        struct g_flow_handle *handle,
        struct g_flow_dp_port_status port_status,
        void *cbk_arg1,
        void *cbk_arg2);

/*! Structure to hold notification from datapath callback functions */
struct g_flow_notification_hooks {
	struct g_flow_cbk_dp_associated_fn  *dp_associated_fn;
	/**< Datapath associated callback function. For every VNF, OpenStack creates DP instance and 
         * exposed to VNF. Once datpath is associated and is ready for VNF, applications rerecieves this event. 
         */

        struct g_flow_cbk_dp_port_status_change_fn *dp_port_status_change_fn;
        /**< Whenever change in the status of the ports attached to dp, this callback function will be called*/

	/**< DP ready received callback function arguments */
	void *dp_ready_rcvd_cbk_arg1;
	void *dp_ready_rcvd_cbk_arg2;

	/**< DP Port status change callback function arguments */
	void *port_status_change_cbk_arg1;
	void *port_status_change_cbk_arg2;
};

/*! Packet notification details from table of given datapath TBD might required to add more fields*/
struct g_flow_packet_notification {
        uint8_t  table_id; /**< Table ID from which packet is received */
        uint32_t packet_len; /**< Length packet data */
        uint8_t  *packet_data; /**< Pointer to packet data */
};

/*! Callback function prototype that application can provide to receive packet from datapath */
typedef void (*g_flow_cbk_packet_received_fn) (
        struct g_flow_handle *handle,
	struct g_flow_packet_notification *in,
        void *cbk_arg1,
        void *cbk_arg2);

/*! Table flow entry information. TBD might required to add more fields*/
struct g_flow_table_flow_entry {
        uint8_t  table_id; /**< Table ID from which packet is received */
        uint16_t priority; /**< priority of flow */
        uint32_t match_field_len; /**< Number of match fields */
        uint32_t  *match_fields; /**< Array of match field IDs of the flow table */
};

/*! Callback function prototype that application can provide to receive flow removed event from datapath */
typedef void (*g_flow_cbk_flow_removed_fn) (
        struct g_flow_handle *handle,
	struct g_flow_table_flow_entry *in, /**> Flow entry that actually removed from table*/
        void *cbk_arg1,
        void *cbk_arg2);

/*! Structure to hold notification from tables of given datapath callback functions */
struct g_flow_table_notification_hooks
{
	/**< Packet received callback function, NULL in case no call back function is required */
	struct g_flow_cbk_packet_received_fn  *pkt_rcvd_fn;
	/**< Flow Removed Callback function, NULL in case no call back function is required */
	struct g_flow_cbk_flow_removed_fn *flow_rmvd_fn;
	
	/**< Packet received callback function arguments */
	void *packet_rcvd_cbk_arg1;
	void *packet_rcvd_cbk_arg2;

	/**< Flow removed received callback function arguments */
	void *flow_rmvd_cbarg_arg1;
	void *flow_rmvd_cbarg_arg2;
};

/*! Table configuration values for the datapath */ 
struct g_flow_table_config_inargs {
  uint8_t id; /**< Table Id value, it can be any value between 0 and 254, it must be unique for the given datapath */ 
  char name[G_FLOW_MAX_TABLE_NAME_LEN]; /**< Name of the table */
  uint32_t max_records; /**< Maximum number of flow records that supported by the table */
  struct g_flow_table_notification_hooks *cbk_hook_fns; /**< Pointer to input structure containing notitication callback function and arguments*/
};

/*! Table match field configuration values for the given table */ 
struct g_flow_table_match_field_config_inargs {
  uint32_t id; /**< Match Field Id  TBD defining list of match fields supported*/
  uint8_t  is_optional; /**< TRUE - if field is optional, FALSE - if field is mandatory */ 
};

/*! Table Match field infourmation */
struct g_flow_match_field_info {
  uint32_t id; /**< Match Field Id  TBD defining list of match fields supported*/
  uint8_t  is_optional; /**< TRUE - if field is optional, FALSE - if field is mandatory */ 
};

/*! Flow Table information */ 
struct g_flow_table_info {
	char name[FLOW_IFNAMESIZ]; /**< Device name */
        uint8_t id; /**< Id of the table */
        uint32_t max_records; /**< Maximum number of flow records that supported by the table */
        uint32_t match_fields_cnt; /**< Total number of match fields supported by the table */
        struct g_flow_match_field_info *match_field_info;
	/**< Array of pointers, where each points to match field specific information */
};

/*! Get flow table details of given datapath inArgs */
struct g_flow_tables_get_inargs {
	uint32_t num_tables; /**< Number of tables to get */
	char *last_table_read; 
	/**< NULL if this is the first time this call is invoked;
          Subsequent calls will have a valid value here */											  
};

/*! Flow tables information get outArgs */
struct g_flow_tables_get_outargs {
	uint32_t num_tables; /**< number of tables to get */
	struct g_flow_table_info *table_info; 						
	/**< Array of pointers, where each points to
	    table specific information */
	char *last_table_read; 
	/**< Send a value that the application can use and
	  * invoke for the next set of tables */
	bool b_more_tables;
	/**< Set if more tables are available */
};

/*! Function prototypes */
/*! 
 * @brief This API returns the API version.
 *
 * @param[in/out] version - Version string
 * 
 * @returns SUCCESS upon SUCCESS or FAILURE 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_api_version(char *version);

/*! 
 * @brief Get the number of available devices 
 *
 * @param[in/out] nr_devices - Number of devices 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_avail_devices_get_num(uint32_t *nr_devices); 

/*!
 * @brief  Get the avaialble device info  
 *
 * @param[in] in -  Pointer to input structure
 *
 * @param[out] out - Pointer to output structure containing device information
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_avail_devices_get_info(
	struct g_flow_avail_devices_get_inargs *in,
	struct g_flow_avail_devices_get_outargs *out);

/*! 
 * @brief Open an datapath device instance in either exclusive or shared mode 
 *
 * @param[in] in - Pointer to input structure
 *
 * @param[out] out -Pointer to output structure with accelerator handle 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_device_open(
	struct g_flow_open_datapath_inargs *in,
	struct g_flow_open_datapath_outargs *out);

/*!
 * @brief Register for notifications from datapath
 *
 * @param[in] handle- datapath handle 
 *
 * @param[in]  in - Pointer to input structure containing notitication callback function and arguments.
 *                  NULL is passed for the functions that are registering.
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_flow_notification_hooks_register (
        struct g_flow_handle *handle,
	const struct g_flow_notification_hooks *in
);

/*! 
 * @brief Get the number of ports that assiged the given datapath 
 *
 * @param[in/out] nr_ports - Number of ports 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_ports_get_num(uint32_t *nr_tables); 

/*!
 * @brief  Get the ports info of given datapath  
 *
 * @param[in] handle- datapath handle 
 *
 * @param[in] in -  Pointer to input structure
 *
 * @param[out] out - Pointer to output structure containing port information
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_ports_get_info(struct g_flow_handle *handle,
                              struct g_flow_dp_ports_get_inargs *in,
	                      struct g_flow_dp_ports_get_outargs *out);

/*! 
 * @brief Add table to previously opened datapath 
 *
 * @param[in] handle- datapath handle 
 * 
 * @param[in] table_cnfg - Pointer to table  configuration values.
 *
 * @param[in] match_fields_cnt - Total number of match fileds configuring for the table 
 *
 * @param[in] match_fields_cnfg - Array of pointers, where each points to match field configurion value for the table 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_table_add(struct g_flow_handle *handle,
                         struct g_flow_table_config_inargs *table_cnfg,
                         uint32_t match_fields_cnt,
                         struct g_flow_table_match_field_config_inargs *match_fields_cnfg);

/*! 
 * @brief Get the number of tables configured for the given datapath 
 *
 * @param[in/out] nr_tables - Number of tables 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_tables_get_num(uint32_t *nr_tables); 

/*!
 * @brief  Get the tables info of given datapath  
 *
 * @param[in] handle- datapath handle 
 *
 * @param[in] in -  Pointer to input structure
 *
 * @param[out] out - Pointer to output structure containing table information
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_FLOW
 */
int32_t g_flow_tables_get_info(struct g_flow_handle *handle,
                               struct g_flow_tables_get_inargs *in,
	                       struct g_flow_tables_get_outargs *out);
/*!
 * @brief Close a previously opened  datapath device  
 *
 * @param[in] handle- datapath handle 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_FLOW
 */

/*TBD adding callback functions at datapath level, currently created only table level */
/*TBD  API for DPReady so that VNF is ready process data from datpath */

int32_t g_flow_device_close(struct g_flow_handle *handle);

#endif
