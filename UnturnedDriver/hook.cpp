#include "hook.h"

bool nullhook::call_kernel_function(void* kernel_function_address)
{
	if (!kernel_function_address)
		return FALSE;

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
		"NtQueryCompositionSurfaceStatistics"));

	if (!function)
		return FALSE;

	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	BYTE shell_code[] = { 0x48, 0x89 };			//mov rdx, xxx
	BYTE shell_code_end[] = { 0xFF, 0xE2 };		//jmp rdx

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	write_to_read_only_memory(function, &orig, sizeof(orig));

	return TRUE;
}

NTSTATUS nullhook::hook_handler(PVOID called_param)
{
	NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;

	if (instructions->req_base == TRUE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instructions->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
		ULONG64 base_address64 = NULL;
		base_address64 = get_module_base_x64(process, ModuleName);
		instructions->base_address = base_address64;
		RtlFreeUnicodeString(&ModuleName);
	}

	else if (instructions->write == TRUE)
	{
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);

			if (!kernelBuff)
				return STATUS_UNSUCCESSFUL;

			if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size))
				return STATUS_UNSUCCESSFUL;

			PEPROCESS process;
			PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
			write_kernel_memory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
			ExFreePool(kernelBuff);
		}
	}

	else if (instructions->read == TRUE)
	{
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			read_kernel_memory((HANDLE)instructions->pid, instructions->address, instructions->output, instructions->size);
		}
	}

	return STATUS_SUCCESS;
}

/*
INT nullhook::FrameRect(HDC hDC, CONST RECT* lprc, HBRUSH hbr)
{
	HBRUSH oldbrush;
	RECT r = *lprc;

	if (!(oldbrush = GdiSelectBrush(hDC, hbr))) return 0;

	PatBlt(hDC, r.left, r.top, 1, r.bottom - r.top, PATCOPY);
	PatBlt(hDC, r.right - 1, r.top, 1, r.bottom - r.top, PATCOPY);
	PatBlt(hDC, r.left, r.top, r.right - r.left, 1, PATCOPY);
	PatBlt(hDC, r.left, r.bottom - 1, r.right - r.left, 1, PATCOPY);

	SelectObject(hDC, oldbrush);
	return TRUE;
}
*/
