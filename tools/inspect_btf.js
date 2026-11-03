#!/usr/bin/env node
'use strict';

// Read-only BTF inspector. Prints evidence; never generates kernel source.
const fs = require('fs');
const crypto = require('crypto');
const path = process.argv[2];
if (!path || process.argv.length !== 3) {
  console.error('Usage: node inspect_btf.js /absolute/path/to/vmlinux.btf');
  process.exit(2);
}
const data = fs.readFileSync(path);
function check(offset, count, limit = data.length) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(count) ||
      offset < 0 || count < 0 || offset + count > limit) {
    throw new Error(`Invalid BTF range: offset=${offset} count=${count} limit=${limit}`);
  }
}
check(0, 24);
if (data.readUInt16LE(0) !== 0xeb9f || data[2] !== 1 || data[3] !== 0) {
  throw new Error('Only little-endian BTF v1 with no flags is supported');
}
const header = data.readUInt32LE(4);
if (header < 24) throw new Error('BTF header is too short');
const typeStart = header + data.readUInt32LE(8);
const typeEnd = typeStart + data.readUInt32LE(12);
const stringStart = header + data.readUInt32LE(16);
const stringLength = data.readUInt32LE(20);
check(typeStart, typeEnd - typeStart);
check(stringStart, stringLength);
function string(offset) {
  check(offset, 1, stringLength);
  const start = stringStart + offset;
  const end = data.indexOf(0, start);
  if (end < start || end >= stringStart + stringLength) throw new Error('Unterminated BTF string');
  return data.toString('utf8', start, end);
}
const kindNames = ['VOID', 'INT', 'PTR', 'ARRAY', 'STRUCT', 'UNION', 'ENUM',
  'FWD', 'TYPEDEF', 'VOLATILE', 'CONST', 'RESTRICT', 'FUNC', 'FUNC_PROTO',
  'VAR', 'DATASEC', 'FLOAT', 'DECL_TAG', 'TYPE_TAG', 'ENUM64'];
const types = [{ id: 0, kind: 0, name: 'void', sizeType: 0 }];
let offset = typeStart;
while (offset < typeEnd) {
  check(offset, 12, typeEnd);
  const info = data.readUInt32LE(offset + 4);
  const type = {
    id: types.length,
    name: string(data.readUInt32LE(offset)),
    kind: (info >>> 24) & 31,
    kflag: (info >>> 31) !== 0,
    vlen: info & 65535,
    sizeType: data.readUInt32LE(offset + 8)
  };
  offset += 12;
  let extra;
  switch (type.kind) {
    case 1: case 14: case 17: extra = 4; break;
    case 3: extra = 12; break;
    case 4: case 5: case 15: case 19: extra = type.vlen * 12; break;
    case 6: case 13: extra = type.vlen * 8; break;
    case 2: case 7: case 8: case 9: case 10: case 11:
    case 12: case 16: case 18: extra = 0; break;
    default: throw new Error(`Unsupported BTF kind ${type.kind}`);
  }
  check(offset, extra, typeEnd);
  if (type.kind === 4 || type.kind === 5) {
    type.members = [];
    for (let i = 0; i < type.vlen; i++) {
      const at = offset + i * 12;
      const bits = data.readUInt32LE(at + 8);
      type.members.push({ name: string(data.readUInt32LE(at)),
        typeId: data.readUInt32LE(at + 4),
        bitOffset: type.kflag ? bits & 0xffffff : bits,
        bitfieldSize: type.kflag ? bits >>> 24 : 0 });
    }
  } else if (type.kind === 13) {
    type.params = [];
    for (let i = 0; i < type.vlen; i++) {
      const at = offset + i * 8;
      type.params.push({ name: string(data.readUInt32LE(at)),
        typeId: data.readUInt32LE(at + 4) });
    }
  } else if (type.kind === 3) {
    type.array = { element: data.readUInt32LE(offset),
      index: data.readUInt32LE(offset + 4), count: data.readUInt32LE(offset + 8) };
  }
  types.push(type);
  offset += extra;
}
if (offset !== typeEnd) throw new Error('BTF type section size mismatch');
function get(id) {
  if (!types[id]) throw new Error(`Unknown BTF type ${id}`);
  return types[id];
}
function describe(id, depth = 0) {
  if (depth > 32) return '<recursive>';
  const type = get(id);
  switch (type.kind) {
    case 2: return `${describe(type.sizeType, depth + 1)} *`;
    case 3: return `${describe(type.array.element, depth + 1)}[${type.array.count}]`;
    case 4: return `struct ${type.name || '<anonymous>'}`;
    case 5: return `union ${type.name || '<anonymous>'}`;
    case 6: case 19: return `enum ${type.name || '<anonymous>'}`;
    case 9: case 10: case 11: case 18:
      return `${kindNames[type.kind].toLowerCase()} ${describe(type.sizeType, depth + 1)}`;
    case 13: return 'function-prototype';
    default: return type.name || kindNames[type.kind];
  }
}
function unwrap(id) {
  for (let count = 0; count < 32; count++) {
    const type = get(id);
    if (![8, 9, 10, 11, 18].includes(type.kind)) return type;
    id = type.sizeType;
  }
  throw new Error('Recursive type qualifiers');
}
function flattened(type, prefix = '', base = 0, depth = 0) {
  if (depth > 16) throw new Error('Too many anonymous aggregate levels');
  const result = [];
  for (const member of type.members || []) {
    const memberType = unwrap(member.typeId);
    const bitOffset = base + member.bitOffset;
    if (!member.name && [4, 5].includes(memberType.kind)) {
      result.push(...flattened(memberType, prefix, bitOffset, depth + 1));
    } else {
      result.push({ name: prefix + member.name, type: describe(member.typeId),
        typeId: member.typeId, byteOffset: bitOffset / 8, bitOffset,
        bitfieldSize: member.bitfieldSize });
    }
  }
  return result;
}
const wanted = {
  mm_struct: ['mmap_lock', 'pgd', 'mm_users', 'mm_count', 'flags', 'mm_lock_seq'],
  task_struct: ['mm', 'active_mm', 'pid', 'tgid'],
  vm_area_struct: ['vm_start', 'vm_end', 'vm_mm', 'vm_flags', 'vm_page_prot', 'vm_file', 'vm_pgoff', 'vm_ops', 'vm_lock', 'vm_lock_seq'],
  file: ['f_inode', 'f_mapping', 'f_mode', 'f_op', 'private_data'],
  inode: ['i_ino', 'i_sb', 'i_mapping', 'i_size', 'i_mode'],
  super_block: ['s_magic', 's_type'],
  address_space: ['host', 'a_ops', 'i_mmap_rwsem'],
  shmem_inode_info: ['seals', 'vfs_inode'],
  rw_semaphore: ['count', 'owner'],
  page: ['flags', '_refcount', '_mapcount', 'mapping', 'index'],
  pt_regs: ['user_regs', 'regs', 'sp', 'pc', 'pstate'],
  userfaultfd_ctx: ['mm'],
  vma_lock: ['lock']
};
const structs = {};
for (const [name, fields] of Object.entries(wanted)) {
  const candidates = types.filter(type => type.kind === 4 && type.name === name);
  structs[name] = candidates.map(type => {
    const all = flattened(type);
    return { typeId: type.id, size: type.sizeType,
      fields: Object.fromEntries(fields.map(field => [field, all.filter(member => member.name === field)])) };
  });
}
const functionNames = ['pin_user_pages_unlocked', 'pin_user_pages', 'pin_user_pages_remote',
  'get_user_pages_unlocked', 'unpin_user_pages', 'get_task_mm', 'mmput', 'find_vma',
  'apply_to_page_range', 'apply_to_existing_page_range', 'change_page_range',
  'copy_to_kernel_nofault', 'copy_from_kernel_nofault', 'copy_from_user_nofault',
  'force_sig', 'down_write', 'up_write', 'do_mem_abort', 'do_page_fault'];
const functions = {};
for (const name of functionNames) {
  functions[name] = types.filter(type => type.kind === 12 && type.name === name).map(type => {
    const proto = get(type.sizeType);
    if (proto.kind !== 13) throw new Error(`Function ${name} has invalid prototype`);
    return { typeId: type.id, returnType: describe(proto.sizeType),
      params: proto.params.map(param => ({ ...param, type: describe(param.typeId) })) };
  });
}
console.log(JSON.stringify({ file: path, bytes: data.length,
  sha256: crypto.createHash('sha256').update(data).digest('hex'),
  typeCount: types.length - 1, structs, functions }, null, 2));
