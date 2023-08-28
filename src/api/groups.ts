

import validator from 'validator';
import privileges from '../privileges';
import events from '../events';
import groups, { logGroupEvent } from '../groups';
import user from '../user';
import meta from '../meta';
import notifications from '../notifications';
import slugify from '../slugify';
import { GroupDataObject } from '../types/group';


interface Caller {
    uid: string
}

interface Data {
    name: string
    ownerUid: string
    system: boolean
}
export default async function create(caller: Caller, data: Data) {
    if (!caller.uid) {
        throw new Error('[[error:no-privileges]]');
    } else if (!data) {
        throw new Error('[[error:invalid-data]]');
    } else if (typeof data.name !== 'string' || groups.isPrivilegeGroup(data.name)) {
        throw new Error('[[error:invalid-group-name]]');
    }

    const canCreate: boolean = await privileges.global.can('group:create', caller.uid) as boolean;
    if (!canCreate) {
        throw new Error('[[error:no-privileges]]');
    }
    data.ownerUid = caller.uid;
    data.system = false;
    // The next line calls a function in a module that has not been updated to TS yet
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    const groupData: GroupDataObject = await groups.create(data) as GroupDataObject;
    // The next line calls a function in a module that has not been updated to TS yet
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    logGroupEvent(caller, 'group-create', {
        groupName: data.name,
    });
    return groupData;
}
