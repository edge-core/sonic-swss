extern "C" {
#include "sai.h"
}

#include "port.h"
#include "swss/logger.h"

extern sai_port_api_t *sai_port_api;
extern sai_acl_api_t* sai_acl_api;
extern sai_object_id_t gSwitchId;

namespace swss {

sai_status_t Port::bindAclTable(sai_object_id_t& group_member_oid, sai_object_id_t table_oid)
{
    sai_status_t status;
    sai_object_id_t groupOid;

    // If port ACL table group does not exist, create one
    if (m_acl_table_group_id == 0)
    {
        sai_object_id_t bp_list[] = { SAI_ACL_BIND_POINT_TYPE_PORT };

        sai_attribute_t group_attrs[3];
        group_attrs[0].id = SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE;
        group_attrs[0].value.s32 = SAI_ACL_STAGE_INGRESS; // TODO: double check
        group_attrs[1].id = SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST;
        group_attrs[1].value.objlist.count = 1;
        group_attrs[1].value.objlist.list = bp_list;
        group_attrs[2].id = SAI_ACL_TABLE_GROUP_ATTR_TYPE;
        group_attrs[2].value.s32 = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL;

        status = sai_acl_api->create_acl_table_group(&groupOid, gSwitchId, 3, group_attrs);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to create ACL table group: %d", status);
            return status;
        }

        m_acl_table_group_id = groupOid;

        // Bind this ACL group to port OID
        sai_attribute_t port_attr;
        port_attr.id = SAI_PORT_ATTR_INGRESS_ACL;
        port_attr.value.oid = groupOid;
        status = sai_port_api->set_port_attribute(m_port_id, &port_attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to bind port %lu to ACL table group %lu: %d",
                    m_port_id, groupOid, status);
            return status;
        }
    }
    else
    {
        groupOid = m_acl_table_group_id;
    }

    // Create an ACL group member with table_oid and groupOid
    sai_attribute_t member_attr[2];
    member_attr[0].id = SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID;
    member_attr[0].value.s32 = groupOid;
    member_attr[1].id = SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID;
    member_attr[1].value.s32 = table_oid;
    member_attr[1].id = SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY;
    member_attr[1].value.s32 = 100; // TODO: double check!

    status = sai_acl_api->create_acl_table_group_member(&group_member_oid, gSwitchId, 2, member_attr);
    if (status != SAI_STATUS_SUCCESS) {
        SWSS_LOG_ERROR("Failed to create member table %lu for ACL table group %lu: %d",
                table_oid, groupOid, status);
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

}
