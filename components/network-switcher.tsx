'use client';
import { CircleHelp, LockKeyhole } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import type { Network } from '@/lib/bulk';

export function NetworkSwitcher({ value, onChange, lockedReason = '' }: { value: Network; onChange: (network: Network) => void; lockedReason?: string }) {
  return <div className="network-control">
    <div className="row between">
      <span className="label">Network</span>
      <TooltipProvider delay={250}><Tooltip>
        <TooltipTrigger className="network-help" aria-label="About Mainnet and Testnet"><CircleHelp size={16}/></TooltipTrigger>
        <TooltipContent className="network-tooltip" side="top" align="end">Mainnet uses real funds. Testnet is for practice. Accounts and keys belong to one network.</TooltipContent>
      </Tooltip></TooltipProvider>
    </div>
    <fieldset className="network-switch" aria-describedby="network-description">
      <legend className="sr-only">Choose network</legend>
      {(['mainnet', 'testnet'] as const).map(network => <label className="network-choice" key={network} htmlFor={`network-${network}`} aria-label={network === 'mainnet' ? 'Mainnet' : 'Testnet'}>
        <input id={`network-${network}`} type="radio" name="bulk-network" value={network} checked={value === network} disabled={!!lockedReason} aria-describedby="network-description" onChange={() => { if (!lockedReason) onChange(network); }}/>
        <span><strong>{network === 'mainnet' ? 'Mainnet' : 'Testnet'}</strong><small>{network === 'mainnet' ? 'Real funds' : 'Practice'}</small></span>
      </label>)}
    </fieldset>
    <p id="network-description" className="hint network-description">{lockedReason ? <><LockKeyhole size={13}/>{lockedReason}</> : value === 'mainnet' ? 'You are using Mainnet. Actions affect your real BULK account.' : 'Use Testnet to try the flow. Testnet keys do not work on Mainnet.'}</p>
  </div>;
}
