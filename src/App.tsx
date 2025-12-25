import React, { useState, useEffect, useRef } from 'react';
import { ethers } from 'ethers';
import { createInstance, SepoliaConfig, initSDK } from '@zama-fhe/relayer-sdk';
import ZetterArtifact from './Zetter.json';
import './App.css';
import gsap from 'gsap';
import { TextPlugin } from 'gsap/TextPlugin';
import { Flip } from 'gsap/all';

gsap.registerPlugin(TextPlugin, Flip);

// Constants
const CONTRACT_ADDRESS = "0xE01fDcEB7a8dD55fA947436b2082f283b964313A";
const ZETTER_ABI = ZetterArtifact.abi;
const SEPOLIA_CHAIN_ID = 11155111;

declare global {
  interface Window {
    gsap: any;
    ethereum?: any;
  }
}

interface VaultData {
  owner: string;
  heartbeat: number;
  lastPing: number;
  beneficiary: string;
  claimed: boolean;
  status: 'active' | 'expired' | 'claimed';
}

function App() {
  // Core State
  const [account, setAccount] = useState<string | null>(null);
  const [contract, setContract] = useState<ethers.Contract | null>(null);
  const [fhevmInstance, setFhevmInstance] = useState<any>(null);
  const [signer, setSigner] = useState<ethers.JsonRpcSigner | null>(null);
  const [view, setView] = useState<'hero' | 'create' | 'vaults' | 'claim'>('hero');
  const [isLoading, setIsLoading] = useState(false);
  const [toast, setToast] = useState<{title: string, msg: string, icon: string} | null>(null);

  // Form State
  const [payloadType, setPayloadType] = useState<'text' | 'file'>('text');
  const [secretText, setSecretText] = useState("");
  const [fileMeta, setFileMeta] = useState<string>("");
  const [durationVal, setDurationVal] = useState<number>(30);
  const [durationUnit, setDurationUnit] = useState<'minutes' | 'days' | 'years'>('days');
  const [beneficiaryInput, setBeneficiaryInput] = useState("");

  // Data State
  const [myVault, setMyVault] = useState<VaultData | null>(null);
  const [watchedVaults, setWatchedVaults] = useState<VaultData[]>([]);
  const [watchInput, setWatchInput] = useState("");
  const [currentTime, setCurrentTime] = useState(Math.floor(Date.now() / 1000));
  const [isEncrypting, setIsEncrypting] = useState(false);

  const loaderRef = useRef<HTMLDivElement>(null);

  // --- INIT ---
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    // Loader Animation
    const tl = gsap.timeline();
    tl.to(".loader-char", { y: 0, opacity: 1, duration: 1, stagger: 0.1, ease: "power4.out" })
      .to("#loader-bar", { x: "0%", duration: 1.5, ease: "expo.inOut" }, "-=0.5")
      .to("#loader", { y: "-100%", duration: 0.8, ease: "power2.in", delay: 0.5, onComplete: () => { if(loaderRef.current) loaderRef.current.style.display = 'none'; } });

    initWeb3();
    loadWatchedVaults();
    // eslint-disable-next-line
  }, []);

  useEffect(() => {
    if (contract && account) {
        const interval = setInterval(() => {
            fetchMyVault();
            refreshWatchedVaults();
        }, 10000);
        return () => clearInterval(interval);
    }
    // eslint-disable-next-line
  }, [contract, account]);

  // View Transitions
  useEffect(() => {
    if (view === 'create') {
        gsap.from(".glass-panel", { y: 20, opacity: 0, duration: 0.6, stagger: 0.1, ease: "power3.out" });
    }
    if (view === 'vaults') {
        gsap.from(".glass-panel", { scale: 0.95, opacity: 0, duration: 0.5, ease: "back.out(1.7)" });
    }
    if (view === 'claim') {
        gsap.from(".glass-panel", { x: -20, opacity: 0, duration: 0.5, ease: "power2.out" });
    }
  }, [view]);

  const initWeb3 = async () => {
    if (window.ethereum) {
      try {
        const provider = new ethers.BrowserProvider(window.ethereum);
        const accounts = await provider.listAccounts();
        
        if (accounts.length > 0) {
            setAccount(accounts[0].address);
        } else {
            return;
        }

        const network = await provider.getNetwork();
        const chainId = Number(network.chainId);
        
        if (chainId !== SEPOLIA_CHAIN_ID) {
            try {
                await window.ethereum.request({
                    method: 'wallet_switchEthereumChain',
                    params: [{ chainId: '0xaa36a7' }],
                });
            } catch (switchError: any) {
                showToast("Error", "Please switch to Sepolia Network", "error");
                return;
            }
        }

        const _signer = await provider.getSigner();
        setSigner(_signer);
        const _contract = new ethers.Contract(CONTRACT_ADDRESS, ZETTER_ABI, _signer);
        setContract(_contract);

        // --- ZAMA FHEVM INIT ---
        try {
            // 1. Initialize WASM (Critical Step)
            await initSDK();
            
            // 2. Create Instance with injected provider
            const instance = await createInstance({
                ...SepoliaConfig,
                network: window.ethereum
            });
            
            setFhevmInstance(instance);
            showToast("System Online", "FHEVM Connected", "wifi");
        } catch (e) {
            console.error("FHEVM Load Error:", e);
            showToast("Warning", "FHEVM failed to load. Check console.", "warning");
        }

        window.ethereum.on('accountsChanged', (accs: string[]) => {
            if(accs.length > 0) {
                window.location.reload();
            }
        });

      } catch (e) {
        console.error("Web3 Init Error", e);
      }
    }
  };

  const connectWallet = async () => {
    if (!window.ethereum) {
        alert("Please install MetaMask!");
        return;
    }
    try {
        await window.ethereum.request({ method: 'eth_requestAccounts' });
        await initWeb3();
        if(view === 'hero') setView('create');
    } catch (e) { console.error(e); }
  };

  // --- ACTIONS ---

  const createVault = async () => {
    if (!contract || !fhevmInstance || !account) return;
    
    if (!beneficiaryInput || !ethers.isAddress(beneficiaryInput)) {
        showToast("Error", "Invalid Beneficiary Address", "error");
        return;
    }

    setIsLoading(true);
    try {
        let seconds = BigInt(durationVal);
        if (durationUnit === 'minutes') seconds *= BigInt(60);
        if (durationUnit === 'days') seconds *= BigInt(86400);
        if (durationUnit === 'years') seconds *= BigInt(31536000);

        const secretPayload = payloadType === 'text' ? secretText : `[FILE] ${fileMeta}`;
        if (!secretPayload) throw new Error("Empty payload");

        setIsEncrypting(true);
        const input = fhevmInstance.createEncryptedInput(CONTRACT_ADDRESS, account);
        
        let secretAsUint;
        try {
            if (/^\d+$/.test(secretPayload)) {
                secretAsUint = BigInt(secretPayload);
            } else {
                const utf8Bytes = ethers.toUtf8Bytes(secretPayload.slice(0, 31)); 
                secretAsUint = BigInt(ethers.hexlify(utf8Bytes));
            }
        } catch(e) {
            secretAsUint = BigInt(123456789); 
        }

        input.add256(secretAsUint);
        
        showToast("Generating Proof", "Constructing Zero-Knowledge Proof (may take ~1-2 mins)...", "psychology");
        
        const encResult = await input.encrypt();
        setIsEncrypting(false);

        // ⭐ NEW: createVault now returns vaultId (we use 0 for simplicity)
        const tx = await contract.createVault(
            seconds, 
            beneficiaryInput, 
            encResult.handles[0], 
            encResult.inputProof
        );
        showToast("Processing", "Creating on-chain vault...", "hourglass_empty");
        await tx.wait();

        showToast("Success", "Vault Created & Encrypted.", "lock");
        setView('vaults');
        fetchMyVault();

    } catch (e: any) {
        console.error(e);
        showToast("Error", e.reason || e.message || "Tx Failed", "error");
    } finally {
        setIsLoading(false);
    }
  };

  const pingVault = async () => {
    if (!contract) return;
    try {
        const vaultId = 0; // ⭐ Using vault 0
        const tx = await contract.ping(vaultId);
        showToast("Sending Heartbeat", "Confirming life signs...", "ecg_heart");
        await tx.wait();
        showToast("Pulse Confirmed", "Timer reset successfully.", "check_circle");
        fetchMyVault();
    } catch (e) {
        showToast("Error", "Ping failed.", "error");
    }
  };

  const claimVault = async (ownerAddr: string) => {
    if (!contract) return;
    try {
        const vaultId = 0; // ⭐ Using vault 0
        const tx = await contract.claim(ownerAddr, vaultId);
        showToast("Claiming", "Attempting to unlock vault...", "key");
        await tx.wait();
        showToast("Success", "Vault claimed! You can now view the secret.", "lock_open");
        refreshWatchedVaults();
    } catch (e: any) {
        console.error(e);
        showToast("Error", "Claim failed (Time not elapsed?)", "error");
    }
  };

  const viewSecret = async (ownerAddr: string) => {
      if (!contract || !fhevmInstance || !account || !signer) {
          showToast("Error", "Wallet or contract not connected", "error");
          return;
      }
      
      try {
          const vaultId = 0;
          
          // STEP 1: Get the encrypted data handle from contract
          console.log("📡 Step 1: Fetching ciphertext handle...");
          showToast("Fetching", "Getting encrypted data from vault...", "cloud_download");
          
          const ciphertextHandle = await contract.getSecret(ownerAddr, vaultId);
          console.log("✅ Ciphertext handle:", ciphertextHandle);
          
          // Validate the handle
          if (!ciphertextHandle || ciphertextHandle === ethers.ZeroHash || ciphertextHandle === "0x") {
              throw new Error("No encrypted data found in vault");
          }

          // STEP 2: Generate temporary keypair for this decryption
          console.log("🔐 Step 2: Generating keypair...");
          showToast("Generating", "Creating decryption keypair...", "vpn_key");
          
          const keypair = fhevmInstance.generateKeypair();
          console.log("✅ Keypair generated");

          // STEP 3: Prepare handle-contract pairs for userDecrypt
          const handleContractPairs = [{
              handle: ciphertextHandle,
              contractAddress: CONTRACT_ADDRESS
          }];
          
          const startTimeStamp = Math.floor(Date.now() / 1000).toString();
          const durationDays = '10'; // Valid for 10 days
          const contractAddresses = [CONTRACT_ADDRESS];

          // STEP 4: Create EIP-712 signature request
          console.log("📝 Step 4: Creating EIP-712 message...");
          const eip712 = fhevmInstance.createEIP712(
              keypair.publicKey,
              contractAddresses,
              startTimeStamp,
              durationDays
          );
          
          // STEP 5: Request signature from user
          console.log("✍️ Step 5: Requesting signature...");
          showToast("Sign Required", "Please sign to decrypt the secret", "draw");
          
          const signature = await signer.signTypedData(
              eip712.domain,
              { UserDecryptRequestVerification: eip712.types.UserDecryptRequestVerification },
              eip712.message
          );
          console.log("✅ Signature obtained:", signature.substring(0, 20) + "...");

          // STEP 6: Request user decryption from Zama gateway
          console.log("🌐 Step 6: Requesting decryption from gateway...");
          showToast("Decrypting", "Requesting from Zama gateway...", "sync");

          const result = await fhevmInstance.userDecrypt(
              handleContractPairs,
              keypair.privateKey,
              keypair.publicKey,
              signature.replace("0x", ""),
              contractAddresses,
              account,
              startTimeStamp,
              durationDays
          );

          console.log("✅ Decryption result:", result);

          // STEP 7: Extract the decrypted value
          const decryptedValue = result[ciphertextHandle];
          
          if (decryptedValue === undefined || decryptedValue === null) {
              throw new Error("Gateway returned empty result");
          }

          // STEP 8: Parse and display the secret
          console.log("🔓 Step 8: Parsing decrypted data...");
          let resultStr = decryptedValue.toString();
          
          // Try to convert from BigInt to readable text
          try {
              const bigIntValue = BigInt(resultStr);
              if (bigIntValue > 0) {
                  const hex = "0x" + bigIntValue.toString(16);
                  // Ensure even length for hex string
                  const paddedHex = hex.length % 2 === 0 ? hex : "0x0" + hex.slice(2);
                  const decodedStr = ethers.toUtf8String(paddedHex);
                  // Clean up null bytes and control characters
                  resultStr = decodedStr.replace(/\0/g, '').trim();
              }
          } catch (e) {
              console.log("⚠️ UTF-8 conversion failed, showing raw value");
          }

          console.log("✅ Final decrypted value:", resultStr);
          showToast("Success", "Secret revealed!", "lock_open");
          
          // Show result in alert
          alert(`🔓 SECRET REVEALED:\n\n${resultStr}`);
          
      } catch (e: any) {
          console.error("❌ Decryption Error:", e);
          
          // More helpful error messages
          let errorMsg = "Decryption failed";
          if (e.message?.includes("NotAuthorized")) {
              errorMsg = "You're not authorized to view this secret";
          } else if (e.message?.includes("vault")) {
              errorMsg = "Vault not found or not claimed yet";
          } else if (e.message) {
              errorMsg = e.message;
          }
          
          showToast("Error", errorMsg, "error");
      }
  };

  // --- DATA FETCHING ---
  const fetchMyVault = async () => {
      if (!contract || !account) return;
      try {
          const vaultId = 0; // ⭐ Using vault 0
          const exists = await contract.hasVault(account, vaultId);
          if (!exists) {
              setMyVault(null);
              return;
          }
          const details = await contract.getVaultDetails(account, vaultId);
          setMyVault({
              owner: account,
              heartbeat: Number(details[0]),
              lastPing: Number(details[1]),
              beneficiary: details[2],
              claimed: details[3],
              status: 'active'
          });
      } catch (e) { console.error(e); }
  };

  const loadWatchedVaults = () => {
      const stored = localStorage.getItem('zellter_watched');
      if (stored) {
          const addresses = JSON.parse(stored);
          setWatchedVaults(addresses.map((a: string) => ({ owner: a, status: 'unknown' })));
      }
  };

  const addWatchVault = () => {
      if(ethers.isAddress(watchInput)) {
          const current = localStorage.getItem('zellter_watched');
          const list = current ? JSON.parse(current) : [];
          if(!list.includes(watchInput)) {
              list.push(watchInput);
              localStorage.setItem('zellter_watched', JSON.stringify(list));
              loadWatchedVaults();
              refreshWatchedVaults();
              showToast("Added", "Vault added to watchlist", "playlist_add");
          }
          setWatchInput("");
      } else {
          showToast("Error", "Invalid address", "error");
      }
  };

  const refreshWatchedVaults = async () => {
      if (!contract) return;
      const stored = localStorage.getItem('zellter_watched');
      if (!stored) return;
      const addresses: string[] = JSON.parse(stored);
      
      const newVaults: VaultData[] = [];
      for (const addr of addresses) {
          try {
              const vaultId = 0; // ⭐ Using vault 0
              const exists = await contract.hasVault(addr, vaultId);
              if (exists) {
                  const d = await contract.getVaultDetails(addr, vaultId);
                  newVaults.push({
                      owner: addr,
                      heartbeat: Number(d[0]),
                      lastPing: Number(d[1]),
                      beneficiary: d[2],
                      claimed: d[3],
                      status: 'active'
                  });
              }
          } catch(e) {}
      }
      setWatchedVaults(newVaults);
  };

  // --- UI HELPERS ---
  const showToast = (title: string, msg: string, icon: string = 'info') => {
      setToast({ title, msg, icon });
      setTimeout(() => setToast(null), 4000);
  };

  const formatTimeRemaining = (lastPing: number, heartbeat: number) => {
      const deadline = lastPing + heartbeat;
      const diff = deadline - currentTime;
      
      if (diff <= 0) return "BREACHED";
      
      const d = Math.floor(diff / 86400);
      const h = Math.floor((diff % 86400) / 3600);
      const m = Math.floor((diff % 3600) / 60);
      const s = diff % 60;
      
      if (d > 0) return `${d}d ${h}h ${m}m`;
      if (h > 0) return `${h}h ${m}m ${s}s`;
      return `${m}m ${s}s`;
  };

  const getProgressWidth = (lastPing: number, heartbeat: number) => {
      const deadline = lastPing + heartbeat;
      const diff = deadline - currentTime;
      if (diff <= 0) return 0;
      const pct = (diff / heartbeat) * 100;
      return Math.min(100, Math.max(0, pct));
  };

  const getStatus = (v: VaultData) => {
      if (v.claimed) return { text: "CLAIMED", color: "bg-gray-500", active: false };
      const now = Math.floor(Date.now() / 1000);
      if (now > v.lastPing + v.heartbeat) return { text: "EXPIRED / UNLOCKED", color: "bg-red-500", active: false };
      return { text: "SECURE", color: "bg-green-500", active: true };
  };

  // --- RENDER ---
  return (
    <>
      <div className="grid-bg"></div>
      
      <div id="loader" ref={loaderRef} className="fixed inset-0 z-[10000] bg-black flex flex-col justify-center items-center text-white">
          <div className="overflow-hidden">
              <h1 className="text-6xl md:text-9xl font-bold font-sans tracking-tighter" id="loader-text">
                  <span className="inline-block translate-y-[100%] opacity-0 loader-char">Z</span>
                  <span className="inline-block translate-y-[100%] opacity-0 loader-char">E</span>
                  <span className="inline-block translate-y-[100%] opacity-0 loader-char">L</span>
                  <span className="inline-block translate-y-[100%] opacity-0 loader-char">L</span>
                  <span className="inline-block translate-y-[100%] opacity-0 loader-char">T</span>
                  <span className="inline-block translate-y-[100%] opacity-0 loader-char">E</span>
                  <span className="inline-block translate-y-[100%] opacity-0 loader-char">R</span>
              </h1>
          </div>
          <div className="mt-8 flex items-center gap-4">
              <div className="w-32 h-[1px] bg-gray-800 relative overflow-hidden">
                  <div className="absolute inset-0 bg-zyellow w-full -translate-x-full" id="loader-bar"></div>
              </div>
              <div className="font-mono text-xs text-gray-500 uppercase tracking-widest">Initializing Vaults</div>
          </div>
      </div>

      <nav className="fixed top-0 w-full z-50 px-6 py-6 transition-all duration-300">
          <div className="max-w-7xl mx-auto flex justify-between items-center glass-panel rounded-full px-8 py-4 border border-white/50 shadow-sm">
              <div className="flex items-center gap-4 group cursor-pointer" onClick={() => window.location.reload()}>
                  <div className="relative w-10 h-10 flex items-center justify-center bg-black rounded-xl overflow-hidden shadow-xl">
                      <span className="font-sans font-bold text-zyellow text-xl z-10">Z</span>
                  </div>
                  <div className="hidden md:flex flex-col">
                      <span className="font-bold tracking-tight text-sm leading-none">ZELLTER</span>
                      <span className="font-mono text-[10px] text-gray-400 leading-none mt-1">PROTOCOL V4.2</span>
                  </div>
              </div>

              <div className="relative group/wallet">
                  <button onClick={account ? undefined : connectWallet} className="btn-core bg-white border border-black text-black px-6 py-2.5 font-bold text-xs uppercase tracking-wider flex items-center gap-2 hover:bg-black hover:text-white transition-all shadow-md overflow-hidden">
                      <span className="relative z-10 flex items-center gap-2">
                          <span className="material-symbols-outlined text-base">wallet</span>
                          <span>{account ? `${account.substring(0,6)}...` : "Connect Wallet"}</span>
                      </span>
                      <div className="absolute inset-0 bg-zyellow translate-y-full group-hover:translate-y-0 transition-transform duration-300"></div>
                  </button>
                  {account && (
                      <div className="absolute top-full right-0 mt-2 w-48 bg-white border border-gray-200 rounded-xl shadow-xl overflow-hidden hidden group-hover/wallet:block animate-fade-in-up">
                          <button onClick={() => { setAccount(null); setView('hero'); showToast("Disconnected", "Wallet disconnected", "link_off"); }} className="w-full text-left px-4 py-3 text-xs font-bold hover:bg-red-50 hover:text-red-600 transition-colors flex items-center gap-2">
                              <span className="material-symbols-outlined text-sm">logout</span> Disconnect
                          </button>
                      </div>
                  )}
              </div>
          </div>
      </nav>

      <main className="relative min-h-screen pt-40 px-4 md:px-12 pb-24 max-w-7xl mx-auto flex flex-col items-center">
        {view === 'hero' && (
           <section className="w-full text-center max-w-4xl mx-auto mb-16 relative perspective-1000 animate-float-slow">
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-white/60 backdrop-blur rounded-full border border-white mb-8">
                  <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-zyellow opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-zyellow"></span>
                  </span>
                  <span className="text-[10px] font-bold tracking-widest text-gray-500 uppercase">System Active • Sepolia</span>
              </div>
              <h1 className="text-6xl md:text-8xl lg:text-[7rem] font-bold leading-[0.9] tracking-tight mb-8">
                  Dead Man's <br/>
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-gray-900 to-gray-500">Switch Protocol.</span>
              </h1>
              <div className="flex justify-center gap-4">
                  <button onClick={() => { connectWallet(); setView('create'); }} className="btn-core bg-black text-white px-8 py-4 rounded-full font-bold text-sm shadow-xl hover:shadow-2xl hover:scale-105 flex items-center gap-3 transition-all shimmer-trigger">
                      Start Vault <span className="material-symbols-outlined">arrow_forward</span>
                  </button>
              </div>
           </section>
        )}

        {view !== 'hero' && (
            <div className="w-full max-w-6xl relative perspective-1000">
                <div className="flex justify-center mb-12 sticky top-32 z-40">
                    <div className="bg-white/90 backdrop-blur p-1.5 rounded-full inline-flex shadow-[0_8px_30px_rgb(0,0,0,0.08)] border border-white">
                        <button onClick={() => setView('create')} className={`px-8 py-2.5 rounded-full text-xs font-bold transition-all ${view === 'create' ? 'bg-black text-white shadow-lg' : 'text-gray-500 hover:text-black'}`}>CREATE</button>
                        <button onClick={() => { setView('vaults'); fetchMyVault(); }} className={`px-8 py-2.5 rounded-full text-xs font-bold transition-all ${view === 'vaults' ? 'bg-black text-white shadow-lg' : 'text-gray-500 hover:text-black'}`}>MY VAULT</button>
                        <button onClick={() => { setView('claim'); refreshWatchedVaults(); }} className={`px-8 py-2.5 rounded-full text-xs font-bold transition-all ${view === 'claim' ? 'bg-black text-white shadow-lg' : 'text-gray-500 hover:text-black'}`}>CLAIM</button>
                    </div>
                </div>

                {view === 'create' && (
                    <div className="grid lg:grid-cols-12 gap-8 items-start animate-fade-in-up">
                        <div className="lg:col-span-7 glass-panel rounded-[2rem] p-8 md:p-12 relative overflow-hidden">
                            <h2 className="text-3xl font-bold mb-8 flex items-center gap-3">
                                <span className="w-2 h-8 bg-black"></span> Configure Vault
                            </h2>
                            <div className="space-y-6">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase">Secret Payload</label>
                                    <div className="flex gap-4 mb-4">
                                        <div onClick={() => setPayloadType('text')} className={`flex-1 cursor-pointer border-2 rounded-xl p-4 flex flex-col items-center gap-2 transition-all ${payloadType==='text' ? 'border-black bg-gray-50' : 'border-gray-200 hover:bg-gray-50'}`}>
                                            <span className="material-symbols-outlined">short_text</span>
                                            <span className="text-xs font-bold">Text</span>
                                        </div>
                                        <div onClick={() => setPayloadType('file')} className={`flex-1 cursor-pointer border-2 rounded-xl p-4 flex flex-col items-center gap-2 transition-all ${payloadType==='file' ? 'border-black bg-gray-50' : 'border-gray-200 hover:bg-gray-50'}`}>
                                            <span className="material-symbols-outlined">attach_file</span>
                                            <span className="text-xs font-bold">File (IPFS)</span>
                                        </div>
                                    </div>
                                    {payloadType === 'text' ? (
                                        <textarea value={secretText} onChange={(e) => setSecretText(e.target.value)} className="z-input h-32 resize-none" placeholder="Enter private keys..."></textarea>
                                    ) : (
                                        <div className="relative h-32 border-2 border-dashed border-gray-300 rounded-xl bg-gray-50 hover:bg-white transition-colors flex flex-col items-center justify-center text-gray-400">
                                            <input type="file" className="absolute inset-0 opacity-0 cursor-pointer" onChange={(e) => { if(e.target.files?.[0]) setFileMeta(e.target.files[0].name); }} />
                                            <span className="material-symbols-outlined text-3xl mb-2">cloud_upload</span>
                                            <span className="text-xs font-bold">{fileMeta || "Click or Drag File"}</span>
                                        </div>
                                    )}
                                </div>
                                <div className="space-y-2 pt-4 border-t border-gray-200">
                                    <label className="text-xs font-bold text-gray-500 uppercase">Heartbeat Timer</label>
                                    <div className="p-6 bg-white rounded-xl border border-gray-200 shadow-sm space-y-4">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="text-4xl font-bold font-mono tracking-tighter">{durationVal}</span>
                                            <div className="z-select-wrapper">
                                                <select value={durationUnit} onChange={(e) => setDurationUnit(e.target.value as any)} className="bg-gray-100 font-bold text-sm px-4 py-2 pr-10 rounded-lg appearance-none cursor-pointer outline-none">
                                                    <option value="minutes">Minutes</option>
                                                    <option value="days">Days</option>
                                                    <option value="years">Years</option>
                                                </select>
                                            </div>
                                        </div>
                                        <input type="range" min="1" max="100" value={durationVal} onChange={(e) => setDurationVal(Number(e.target.value))} className="accent-black w-full" />
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="lg:col-span-5 space-y-6">
                            <div className="glass-panel rounded-[2rem] p-8 shadow-xl">
                                <label className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3 block">Beneficiary Address</label>
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-purple-400 to-blue-500 shadow-inner"></div>
                                    <input type="text" value={beneficiaryInput} onChange={(e) => setBeneficiaryInput(e.target.value)} placeholder="0x..." className="flex-1 bg-transparent border-b-2 border-gray-200 focus:border-black font-mono text-sm py-2 outline-none transition-colors" />
                                </div>
                            </div>
                            <button onClick={createVault} disabled={isLoading} className="w-full group relative overflow-hidden bg-black text-white rounded-[1.5rem] p-6 text-left shadow-2xl transition-all hover:scale-[1.02]">
                                <div className="relative z-10 flex justify-between items-center">
                                    <div>
                                        <div className="text-2xl font-bold text-zyellow mb-1">
                                            {isLoading ? (isEncrypting ? "Generating Proof..." : "Confirming...") : "Lock Vault"}
                                        </div>
                                        <div className="text-xs text-gray-400 font-mono">
                                            {isEncrypting ? "Please wait (~1-2 min)" : "0.02 ETH GAS FEE"}
                                        </div>
                                    </div>
                                    <div className="w-12 h-12 rounded-full border border-gray-600 flex items-center justify-center group-hover:bg-zyellow group-hover:text-black">
                                        <span className="material-symbols-outlined">lock</span>
                                    </div>
                                </div>
                            </button>
                        </div>
                    </div>
                )}

                {view === 'vaults' && (
                    <div className="glass-panel rounded-[2.5rem] min-h-[400px] p-8">
                        <h2 className="text-4xl font-bold mb-8">Your Vault</h2>
                        {!myVault ? (
                             <div className="text-center py-20">
                                <div className="w-20 h-20 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                    <span className="material-symbols-outlined text-3xl text-gray-400">lock_open</span>
                                </div>
                                <h3 className="font-bold text-gray-400">No active vault found.</h3>
                                <button className="mt-4 text-xs font-bold underline" onClick={() => setView('create')}>Create one</button>
                            </div>
                        ) : (
                            <div className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm flex flex-col gap-6">
                                <div className="flex justify-between items-start">
                                    <div>
                                        <h3 className="text-2xl font-bold">#VAULT-1</h3>
                                        <p className="text-xs text-gray-400 font-mono">BENEFICIARY: {myVault.beneficiary}</p>
                                    </div>
                                    <div className={`px-3 py-1 text-white text-xs font-bold rounded-full ${getStatus(myVault).color}`}>
                                        {getStatus(myVault).text}
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <div className="w-full bg-gray-100 rounded-full h-3 overflow-hidden relative">
                                        <div 
                                            className="h-full bg-black transition-all duration-1000 ease-linear relative overflow-hidden" 
                                            style={{width: `${getProgressWidth(myVault.lastPing, myVault.heartbeat)}%`}}
                                        >
                                            <div className="absolute inset-0 bg-white/20 animate-pulse-fast"></div>
                                        </div>
                                    </div>
                                    <div className="flex justify-between text-xs font-mono">
                                        <span className="text-gray-400 font-bold">TTL (TIME TO LIVE)</span>
                                        <span className="font-bold text-lg">{formatTimeRemaining(myVault.lastPing, myVault.heartbeat)}</span>
                                    </div>
                                </div>
                                <button onClick={pingVault} className="w-full py-4 bg-zyellow hover:bg-black hover:text-white transition-colors text-black font-bold rounded-xl flex items-center justify-center gap-2">
                                     <span className="material-symbols-outlined animate-pulse">ecg_heart</span> CONFIRM LIFE (PING)
                                </button>
                            </div>
                        )}
                    </div>
                )}

                {view === 'claim' && (
                    <div className="glass-panel rounded-[2.5rem] min-h-[400px] p-8">
                         <div className="flex justify-between items-center mb-8">
                            <h2 className="text-4xl font-bold">Claim</h2>
                            <button onClick={refreshWatchedVaults} className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center hover:bg-black hover:text-white transition-all"><span className="material-symbols-outlined">refresh</span></button>
                        </div>
                        <div className="mb-8 flex gap-4">
                            <input type="text" value={watchInput} onChange={(e) => setWatchInput(e.target.value)} placeholder="Enter Owner Address to Watch..." className="flex-1 bg-white border-2 border-gray-200 rounded-xl px-4 py-3 font-mono text-sm outline-none focus:border-black" />
                            <button onClick={addWatchVault} className="bg-black text-white px-6 rounded-xl font-bold text-sm hover:scale-105 transition-transform">Add</button>
                        </div>
                        <div className="grid md:grid-cols-2 gap-6">
                            {watchedVaults.map((v, i) => (
                                <div key={i} className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm hover:shadow-lg transition-all">
                                    <div className="mb-4">
                                        <h3 className="text-lg font-bold truncate">Owner: {v.owner.substring(0,8)}...</h3>
                                        <div className="flex items-center gap-2 mt-2">
                                            <span className={`w-2 h-2 rounded-full ${getStatus(v).color}`}></span>
                                            <span className="text-xs font-bold text-gray-500">{getStatus(v).text}</span>
                                        </div>
                                    </div>
                                    <div className="flex gap-2">
                                        {!v.claimed && getStatus(v).active === false ? (
                                             <button onClick={() => claimVault(v.owner)} className="flex-1 py-3 bg-black text-white font-bold rounded-xl hover:bg-zyellow hover:text-black transition-colors">CLAIM</button>
                                        ) : v.claimed ? (
                                            <button onClick={() => viewSecret(v.owner)} className="flex-1 py-3 bg-gray-900 text-white font-bold rounded-xl hover:bg-gray-800 transition-colors flex items-center justify-center gap-2">
                                                <span className="material-symbols-outlined text-sm">visibility</span> VIEW SECRET
                                            </button>
                                        ) : (
                                            <button disabled className="flex-1 py-3 bg-gray-100 text-gray-400 font-bold rounded-xl cursor-not-allowed">LOCKED</button>
                                        )}
                                    </div>
                                </div>
                            ))}
                            {watchedVaults.length === 0 && (
                                <div className="col-span-full text-center text-gray-400 text-sm py-10">Add an address to check for inheritance.</div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        )}
      </main>

      <div id="toast" className={`fixed bottom-8 right-8 z-[10000] transition-transform duration-500 flex items-center gap-4 bg-white px-6 py-4 rounded-xl shadow-2xl border-l-4 border-black ${toast ? 'translate-y-0' : 'translate-y-40'}`}>
          <div className="w-8 h-8 rounded-full bg-black flex items-center justify-center text-zyellow">
              <span className="material-symbols-outlined text-sm">{toast?.icon || 'info'}</span>
          </div>
          <div>
              <h4 className="font-bold text-sm">{toast?.title}</h4>
              <p className="text-xs text-gray-500">{toast?.msg}</p>
          </div>
      </div>
    </>
  );
}

export default App;