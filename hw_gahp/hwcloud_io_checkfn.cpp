/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#include "condor_common.h"
#include "condor_debug.h"
#include "condor_config.h"
#include "condor_string.h"
#include "string_list.h"
#include "condor_arglist.h"
#include "util_lib_proto.h"
#include "internet.h"
#include "basename.h"
#include "hwcloudgahp_common.h"
#include "hwcloudCommands.h"

// Expecting:
// EC2_VM_START <req-id> <service-url> <accesskeyfile> <secretkeyfile>
//              <ami-id> <keypair> <userdata> <userdatafile> <instance-type>
//				<availability-zone> <vpc-subnet> <vpc-ip> <client-token>
//				<block-device-mapping> <iam-profile-arn> <iam-profile-name>
//				<max-count>
//              <security-group-name>* <NULLSTRING>
//              <security-group-id>* <NULLSTRING>
//				<parameters-and-values>* <NULLSTRING>
bool HwcloudVMStart::ioCheck(char **argv, int argc)
{
	return verify_min_number_args(argc, 21) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]) &&
		verify_string_name(argv[6]) &&
		verify_string_name(argv[7]) &&
		verify_string_name(argv[8]) &&
		verify_string_name(argv[9]) &&
		verify_string_name(argv[10]) &&
		verify_string_name(argv[11]) &&
		verify_string_name(argv[12]) &&
		verify_string_name(argv[13]) &&
		verify_string_name(argv[14]) &&
		verify_string_name(argv[15]) &&
		verify_string_name(argv[16]) &&
		verify_number(argv[17]) &&
		verify_string_name(argv[18]) &&
		verify_string_name(argv[19]) &&
		verify_string_name(argv[20]);
}

// Expecting:EC2_VM_START_SPOT <req_id>
// <serviceurl> <accesskeyfile> <secretkeyfile>
// <ami-id> <spot-price> <keypair> <userdata> <userdatafile>
//          <instancetype> <availability_zone> <vpc_subnet> <vpc_ip>
//          <client-token> <iam-profile-arn> <iam-profile-name>
//			<groupname>* <NULLSTRING> <groupid>* <NULLSTRING>
bool HwcloudVMStartSpot::ioCheck(char **argv, int argc)
{
	return verify_min_number_args(argc, 19) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]) &&
		verify_string_name(argv[6]) &&
		verify_string_name(argv[7]) &&
		verify_string_name(argv[8]) &&
		verify_string_name(argv[9]) &&
		verify_string_name(argv[10]) &&
		verify_string_name(argv[11]) &&
		verify_string_name(argv[12]) &&
		verify_string_name(argv[13]) &&
		verify_string_name(argv[14]) &&
		verify_string_name(argv[15]) &&
		verify_string_name(argv[16]) &&
		verify_string_name(argv[17]) &&
		verify_string_name(argv[18]);
}

// Expecting:EC2_VM_STOP <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id>
bool HwcloudVMStop::ioCheck(char **argv, int argc)
{
	return verify_min_number_args(argc, 6) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]);
}

// Expecting:EC2_VM_STATUS <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id>
bool HwcloudVMStatus::ioCheck(char **argv, int argc)
{
	return verify_number_args(argc, 6) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]);
}

bool HwcloudVMStatusAllSpot::ioCheck(char **argv, int argc)
{
	return verify_min_number_args(argc, 5) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]);
}

// Expecting:EC2_VM_ASSOCIATE_ADDRESS  <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id> <elastic-ip> 
bool HwcloudAssociateAddress::ioCheck(char **argv, int argc)
{
    return verify_number_args(argc, 7) &&
        verify_request_id(argv[1]) &&
        verify_string_name(argv[2]) &&
        verify_string_name(argv[3]) &&
        verify_string_name(argv[4]) &&
        verify_string_name(argv[5]) && 
        verify_string_name(argv[6]);
}

// Expecting:EC2_VM_ATTACH_VOLUME <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <volume-id> <instance-id> <device-id>
bool HwcloudAttachVolume::ioCheck(char **argv, int argc)
{
    return verify_number_args(argc, 8) &&
        verify_request_id(argv[1]) &&
        verify_string_name(argv[2]) &&
        verify_string_name(argv[3]) &&
        verify_string_name(argv[4]) &&
        verify_string_name(argv[5]) && 
        verify_string_name(argv[6]) && 
        verify_string_name(argv[7]);
}

// Expecting:EC2_VM_STATUS_ALL <req_id> <serviceurl> <accesskeyfile> <secretkeyfile>
bool HwcloudVMStatusAll::ioCheck(char **argv, int argc)
{
	return verify_min_number_args(argc, 5) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]);
}

// Expecting:EC2_VM_CREATE_KEYPAIR <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <keyname> <outputfile>
bool HwcloudVMCreateKeypair::ioCheck(char **argv, int argc)
{
	return verify_number_args(argc, 7) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]) &&
		verify_string_name(argv[6]);
}

// Expecting:EC2_VM_DESTROY_KEYPAIR <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <keyname>
bool HwcloudVMDestroyKeypair::ioCheck(char **argv, int argc)
{
	return verify_number_args(argc, 6) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]);
}

// Expecting:EC2_VM_SERVER_TYPE <req_id> <serviceurl> <accesskeyfile> <secretkeyfile>
bool HwcloudVMServerType::ioCheck(char **argv, int argc)
{
	return verify_number_args(argc, 5) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]);
}

// Expecting:	EC2_BULK_START <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<client-token> <spot-price> <target-capacity>
//				<iam-fleet-role> <allocation-strategy> <valid-until>
//				<launch-configuration-json-blob>+ <NULLSTRING>
bool HwcloudBulkStart::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 13 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] ) &&
		verify_string_name( argv[6] ) &&
		verify_string_name( argv[7] ) &&
		verify_string_name( argv[8] ) &&
		verify_string_name( argv[9] ) &&
		verify_string_name( argv[10] ) &&
		verify_string_name( argv[11] ) &&
		verify_string_name( argv[12] );
}

// Expecting:	CWE_PUT_RULE <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<rule-name> <schedule-expression> <desired-state>
bool HwcloudPutRule::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 8 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] ) &&
		verify_string_name( argv[6] ) &&
		verify_string_name( argv[7] );
}

// Expecting:	CWE_PUT_TARGETS <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<rule-name> <target-id> <target-arn> <target-input>
bool HwcloudPutTargets::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 9 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] ) &&
		verify_string_name( argv[6] ) &&
		verify_string_name( argv[7] ) &&
		verify_string_name( argv[8] );
}

// Expecting:	EC2_BULK_STOP <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<bulk-request-id>
bool HwcloudBulkStop::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 6 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] );
}

// Expecting:	CWE_DELETE_RULE <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<rule-name>
bool HwcloudDeleteRule::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 6 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] );
}

// Expecting:	CWE_REMOVE_TARGETS <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<rule-name> <target-id>
bool HwcloudRemoveTargets::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 7 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] ) &&
		verify_string_name( argv[6] );
}

// Expecting:	AWS_GET_FUNCTION <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<function-name-or-arn>
bool HwcloudGetFunction::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 6 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] );
}

// Expecting:	S3_UPLOAD <req_id>
//				<serviceurl> <accesskeyfile> <secretkeyfile>
//				<bucketName> <fileName> <path>
bool HwcloudS3Upload::ioCheck(char **argv, int argc)
{
	return verify_number_args(argc, 8) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]) &&
		verify_string_name(argv[6]) &&
		verify_string_name(argv[7]);
}

// Expecting:	CF_CREATE_STACK <req_id>
//				<serviceurl> <accesskeyfile> <secretkeyfile>
//				<stackName> <templateURL> <capability>
//				(<parameters-name> <parameter-value>)* <NULLSTRING>
bool HwcloudCreateStack::ioCheck(char **argv, int argc)
{
	return verify_min_number_args(argc, 9) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]) &&
		verify_string_name(argv[6]) &&
		verify_string_name(argv[7]) &&
		verify_string_name(argv[8]);
}

// Expecting:	CF_DESCRIBE_STACKS <req_id>
//				<serviceurl> <accesskeyfile> <secretkeyfile>
//				<stackName>
bool HwcloudDescribeStacks::ioCheck(char **argv, int argc)
{
	return verify_number_args(argc, 6) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]);
}

// Expecting:	AWS_CALL_FUNCTION <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
//				<function-name-or-arn> <function-argument-blob>
bool HwcloudCallFunction::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 7 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] ) &&
		verify_string_name( argv[5] ) &&
		verify_string_name( argv[6] );
}

// Expecting:	EC2_BULK_QUERY <req_id>
//				<service_url> <accesskeyfile> <secretkeyfile>
bool HwcloudBulkQuery::ioCheck(char **argv, int argc) {
	return verify_min_number_args( argc, 5 ) &&
		verify_request_id( argv[1] ) &&
		verify_string_name( argv[2] ) &&
		verify_string_name( argv[3] ) &&
		verify_string_name( argv[4] );
}
