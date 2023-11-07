.. SPDX-License-Identifier: GPL-2.0

==============================
Emulating Hyper-V VSM with KVM
==============================

Hyper-V's Virtual Secure Mode (VSM) is a virtualisation security feature
that leverages the hypervisor to create secure execution environments
within a guest. VSM is documented as part of Microsoft's Hypervisor Top
Level Functional Specification[1].

Emulating Hyper-V's Virtual Secure Mode with KVM requires coordination
between KVM and the VMM. Most of the VSM state and configuration is left
to be handled by user-space, but some has made its way into KVM. This
document describes the mechanisms through which a VMM can implement VSM
support.

Virtual Trust Levels
--------------------

The main concept VSM introduces are Virtual Trust Levels or VTLs. Each
VTL is a CPU mode, with its own private CPU architectural state,
interrupt subsystem (limited to a local APIC), and memory access
permissions. VTLs are hierarchical, where VTL0 corresponds to normal
guest execution and VTL > 0 to privileged execution contexts. In
practice, when virtualising Windows on top of KVM, we only see VTL0 and
VTL1. Although the spec allows going all the way to VTL15. VTLs are
orthogonal to ring levels, so each VTL is capable of runnig its own
operating system and user-space[2].

  ┌──────────────────────────────┐ ┌──────────────────────────────┐
  │ Normal Mode (VTL0)           │ │ Secure Mode (VTL1)           │
  │ ┌──────────────────────────┐ │ │ ┌──────────────────────────┐ │
  │ │   User-mode Processes    │ │ │ │Secure User-mode Processes│ │
  │ └──────────────────────────┘ │ │ └──────────────────────────┘ │
  │ ┌──────────────────────────┐ │ │ ┌──────────────────────────┐ │
  │ │         Kernel           │ │ │ │      Secure Kernel       │ │
  │ └──────────────────────────┘ │ │ └──────────────────────────┘ │
  └──────────────────────────────┘ └──────────────────────────────┘
  ┌───────────────────────────────────────────────────────────────┐
  │                         Hypervisor/KVM                        │
  └───────────────────────────────────────────────────────────────┘
  ┌───────────────────────────────────────────────────────────────┐
  │                           Hardware                            │
  └───────────────────────────────────────────────────────────────┘

VTLs break the core assumption that a vCPU has a single architectural
state, lAPIC state, SynIC state, etc. As such, each VTL is modeled as a
distinct KVM vCPU, with the restriction that only one is allowed to run
at any moment in time. Having multiple KVM vCPUs tracking a single guest
CPU complicates vCPU numbering. VMs that enable VSM are expected to use
CAP_APIC_ID_GROUPS to segregate vCPUs (and their lAPICs) into different
groups. For example, a 4 CPU VSM VM will setup the APIC ID groups feature
so only the first two bits of the APIC ID are exposed to the guest. The
remaining bits represent the vCPU's VTL. The 'sibling' vCPU to VTL0's
vCPU2 at VTL3 will have an APIC ID of 0xE. Using this approach a VMM and
KVM are capable of querying a vCPU's VTL, or finding the vCPU associated
to a specific VTL.

KVM's lAPIC implementation is aware of groups, and takes note of the
source vCPU's group when delivering IPIs. As such, it shouldn't be
possible to target a different VTL through the APIC. Interrupts are
delivered to the vCPU's lAPIC subsystem regardless of the VTL's runstate,
this also includes timers. Ultimately, any interrupt incoming from an
outside source (IOAPIC/MSIs) is routed to VTL0.

Moving Between VTLs
-------------------

All VSM configuration and VTL handling hypercalls are passed through to
user-space. Notably the two primitives that allow switching between VTLs.
All shared state synchronization and KVM vCPU scheduling is left to the
VMM to manage. For example, upon receiving a VTL call, the VMM stops the
vCPU that issued the hypercall, and schedules the vCPU corresponding to
the next privileged VTL. When that privileged vCPU is done executing, it
issues a VTL return hypercall, so the opposite operation happens. All
this is transparent to KVM, which limits itself to running vCPUs.

An interrupt directed at a privileged VTL always has precedence over the
execution of lower VTLs. To honor this, the VMM can monitor events
targeted at privileged vCPUs with poll(), and should trigger an
asynchronous VTL switch whenever events become available. Additionally,
the target VTL's vCPU VP assist overlay page is used to notify the target
VTL with the reason for the switch. The VMM can keep track of the VP
assist page by installing an MSR filter for HV_X64_MSR_VP_ASSIST_PAGE.

Hyper-V VP registers
--------------------

VP register hypercalls are passed through to user-space. All requests can
be fulfilled either by using already existing KVM state ioctls, or are
related to VSM's configuration, which is already handled by the VMM. Note
that HV_REGISTER_VSM_CODE_PAGE_OFFSETS is the only VSM specific VP
register the kernel controls, as such it is made available through the
KVM_HV_GET_VSM_STATE ioctl.

Per-VTL Memory Protections
--------------------------

A privileged VTL can change the memory access restrictions of lower VTLs.
It does so to hide secrets from them, or to control what they are allowed
to execute. The list of memory protections allowed is[3]:
 - No access
 - Read-only, no execute
 - Read-only, execute
 - Read/write, no execute
 - Read/write, execute

VTL memory protection hypercalls are passed through to user-space, but
KVM provides an interface that allows changing memory protections on a
per-VTL basis. This is made possible by the KVM VTL device. VMMs can
create one per VTL and it exposes a ioctl, KVM_SET_MEMORY_ATTRIBUTES,
that controls the memory protections applied to that VTL. The KVM TDP MMU
is VTL aware and page faults are resolved taking into account the
corresponding VTL device's memory attributes.

When a memory access violates VTL memory protections, KVM issues a secure
memory intercept, which is passed as a SynIC message into the next
privileged VTL. This happens transparently for the VMM. Additionally, KVM
exits with a user-space memory fault. This allows the VMM to stop the
vCPU while the secure intercept is handled by the privileged VTL. In the
good case, the instruction that triggered the fault is emulated and
control is returned to the lower VTL, in the bad case, Windows crashes
gracefully.

Hyper-V's TLFS also states that DMA should follow VTL0's memory access
restrictions. This is out of scope for this document, as IOMMU mappings
are not handled by KVM.

[1] https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/master/tlfs/Hypervisor%20Top%20Level%20Functional%20Specification%20v6.0b.pdf

[2] Conceptually this design is similar to arm's TrustZone: The
hypervisor plays the role of EL3. Windows (VTL0) runs in Non-Secure
(EL0/EL1) and the secure kernel (VTL1) in Secure World (EL1s/EL0s).

[3] TLFS 15.9.3
