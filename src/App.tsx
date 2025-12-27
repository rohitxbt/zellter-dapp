import React, { useState, useEffect, useRef } from 'react';
import { ethers } from 'ethers';
import { createInstance, SepoliaConfig, initSDK } from '@zama-fhe/relayer-sdk';
import { PrivyProvider, usePrivy, useWallets } from '@privy-io/react-auth';
import ZetterArtifact from './Zetter.json';
import './App.css';
import gsap from 'gsap';
import { TextPlugin } from 'gsap/TextPlugin';
import { Flip } from 'gsap/all';
import { uploadToIPFS, fetchFromIPFS } from './utils/ipfs';
import { generateAESKey, encryptFile, decryptFile, exportKey, importKey, arrayBufferToBase64, base64ToArrayBuffer } from './utils/encryption';

gsap.registerPlugin(TextPlugin, Flip);

// Constants
const CONTRACT_ADDRESS = "0x2EF543704138e5a7fd65430fcCE0cef6c84bF101";
const ZETTER_ABI = ZetterArtifact.abi;
const SEPOLIA_CHAIN_ID = 11155111;
const PRIVY_APP_ID = "cmjmgu9k001c5ky0c3hoppj1m";

// Enums matching contract
const PayloadType = { TEXT: 0, FILE: 1 };
const StorageMode = { ONCHAIN_FHE: 0, OFFCHAIN_IPFS: 1 };

interface VaultData {
  id: number;
  owner: string;
  heartbeat: number;
  lastPing: number;
  beneficiary: string;
  claimed: boolean;
  status: 'active' | 'expired' | 'claimed';
  payloadType: number;
  storageMode: number;
}

function InnerApp() {
  // Privy Hooks
  const { login, authenticated, user, logout } = usePrivy();
  const { wallets } = useWallets();

  // Core State
  const [account, setAccount] = useState<string | null>(null);
  const [contract, setContract] = useState<ethers.Contract | null>(null);
  const [fhevmInstance, setFhevmInstance] = useState<any>(null);
  const [signer, setSigner] = useState<ethers.JsonRpcSigner | null>(null);
  
  const [view, setView] = useState<'hero' | 'create' | 'vaults' | 'claim'>('hero');
  const [isLoading, setIsLoading] = useState(false); // General loading (txs)
  const [isFHELoading, setIsFHELoading] = useState(false); // Specific for FHE (custom loader)
  const [toast, setToast] = useState<{title: string, msg: string, icon: string} | null>(null);

  // Form State
  const [payloadType, setPayloadType] = useState<number>(PayloadType.TEXT);
  const [storageMode, setStorageMode] = useState<number>(StorageMode.ONCHAIN_FHE);
  const [secretText, setSecretText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [fileMeta, setFileMeta] = useState<string>("");
  const [durationVal, setDurationVal] = useState<number>(30);
  const [durationUnit, setDurationUnit] = useState<'minutes' | 'days' | 'years'>('days');
  const [beneficiaryInput, setBeneficiaryInput] = useState("");

  // Data State
  const [myVaults, setMyVaults] = useState<VaultData[]>([]);
  const [watchedVaults, setWatchedVaults] = useState<VaultData[]>([]);
  const [currentTime, setCurrentTime] = useState(Math.floor(Date.now() / 1000));
  
  // UI State
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  
  const loaderRef = useRef<HTMLDivElement>(null);

  // --- INIT ---
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    // Initial App Loader Animation
    const tl = gsap.timeline();
    tl.to(".loader-char", { y: 0, opacity: 1, duration: 1, stagger: 0.1, ease: "power4.out" })
      .to("#loader-bar", { x: "0%", duration: 1.5, ease: "expo.inOut" }, "-=0.5")
      .to("#loader", { y: "-100%", duration: 0.8, ease: "power2.in", delay: 0.5, onComplete: () => { if(loaderRef.current) loaderRef.current.style.display = 'none'; } });
  }, []);

  // Web3 Init Logic (Privy Driven)
  useEffect(() => {
    async function init() {
      if (authenticated && wallets.length > 0) {
        const wallet = wallets[0];
        const addr = wallet.address;
        setAccount(addr);
        if (view === 'hero') setView('create');

        try {
          // Switch chain if needed
          const chainId = Number(wallet.chainId).toString().includes('11155111') ? 11155111 : parseInt(wallet.chainId.split(':')[1]);
          if (chainId !== SEPOLIA_CHAIN_ID) {
              await wallet.switchChain(SEPOLIA_CHAIN_ID);
          }

          // Ethers Provider from Privy
          const ethProvider = await wallet.getEthereumProvider();
          const provider = new ethers.BrowserProvider(ethProvider);
          const _signer = await provider.getSigner();
          setSigner(_signer);
          
          const _contract = new ethers.Contract(CONTRACT_ADDRESS, ZETTER_ABI, _signer);
          setContract(_contract);

          // ZAMA FHEVM INIT
          try {
              await initSDK();
              const instance = await createInstance({
                  ...SepoliaConfig,
                  network: ethProvider
              });
              setFhevmInstance(instance);
              showToast("System Online", "FHEVM Connected", "wifi");
          } catch (e) {
              console.error("FHEVM Load Error:", e);
          }

        } catch (e) {
          console.error("Privy Init Error", e);
        }
      } else if (!authenticated) {
        setAccount(null);
        setContract(null);
        setSigner(null);
      }
    }
    init();
    // eslint-disable-next-line
  }, [authenticated, wallets]); // Re-run when wallet connects

  useEffect(() => {
    if (contract && account) {
        fetchMyVaults();
        fetchBeneficiaryVaults();
        const interval = setInterval(() => {
            fetchMyVaults();
            fetchBeneficiaryVaults();
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


  // --- ACTIONS ---

  const handleConnect = () => {
      login();
  };

  const createVault = async () => {
    if (!contract || !account) return;
    
    if (!beneficiaryInput || !ethers.isAddress(beneficiaryInput)) {
        showToast("Error", "Invalid Beneficiary Address", "error");
        return;
    }

    if (payloadType === PayloadType.FILE && !file) {
        showToast("Error", "Please select a file", "error");
        return;
    }

    if (payloadType === PayloadType.TEXT && !secretText) {
        showToast("Error", "Please enter a secret message", "error");
        return;
    }

    setIsLoading(true);
    let keyToBackup = "";

    try {
        let seconds = BigInt(durationVal);
        if (durationUnit === 'minutes') seconds *= BigInt(60);
        if (durationUnit === 'days') seconds *= BigInt(86400);
        if (durationUnit === 'years') seconds *= BigInt(31536000);

        let encryptedSecretHandle: string | bigint = ethers.ZeroHash;
        let inputProof = "0x";
        let cid = "";

        // Encryption Logic
        if (storageMode === StorageMode.ONCHAIN_FHE) {
            if (!fhevmInstance) throw new Error("FHEVM not initialized");
            
            // SHOW CUSTOM LOADER FOR FHE
            setIsFHELoading(true);

            // Wait a bit to let UI render the loader before heavy calc
            await new Promise(r => setTimeout(r, 100));

            const input = fhevmInstance.createEncryptedInput(CONTRACT_ADDRESS, account);
            
            let secretAsUint;
            try {
                if (/^\d+$/.test(secretText)) {
                    secretAsUint = BigInt(secretText);
                } else {
                    const utf8Bytes = ethers.toUtf8Bytes(secretText.slice(0, 31)); 
                    secretAsUint = BigInt(ethers.hexlify(utf8Bytes));
                }
            } catch(e) {
                secretAsUint = BigInt(123456789); 
            }

            input.add256(secretAsUint);
            
            showToast("Generating Proof", "Constructing Zero-Knowledge Proof...", "psychology");
            const encResult = await input.encrypt();
            encryptedSecretHandle = encResult.handles[0];
            inputProof = encResult.inputProof;
            
            setIsFHELoading(false); // Hide custom loader

        } else {
            // OFFCHAIN_IPFS
            showToast("Encrypting", "Encrypting file/text locally...", "lock");
            
            // 1. Generate Key
            const key = await generateAESKey();
            const exportedKey = await exportKey(key);
            keyToBackup = exportedKey;
            
            // 2. Encrypt Content
            let blobToUpload: Blob;
            let iv: Uint8Array;
            
            if (payloadType === PayloadType.FILE && file) {
                const enc = await encryptFile(file, key);
                blobToUpload = enc.encryptedBlob;
                iv = enc.iv;
            } else {
                const textBlob = new Blob([secretText], { type: 'text/plain' });
                const textFile = new File([textBlob], "secret.txt");
                const enc = await encryptFile(textFile, key);
                blobToUpload = enc.encryptedBlob;
                iv = enc.iv;
            }

            // 3. Prepare Metadata
            const ivBase64 = arrayBufferToBase64(iv);
            
            const fileReader = new FileReader();
            fileReader.readAsDataURL(blobToUpload);
            await new Promise(r => fileReader.onload = r);
            const base64Data = fileReader.result as string;

            const payload = JSON.stringify({
                iv: ivBase64,
                data: base64Data,
                type: payloadType === PayloadType.FILE ? file?.type : 'text/plain',
                name: payloadType === PayloadType.FILE ? file?.name : 'secret.txt'
            });

            const finalFile = new File([payload], "encrypted_payload.json", { type: "application/json" });

            // 4. Upload to IPFS
            showToast("Uploading", "Uploading to IPFS...", "cloud_upload");
            cid = await uploadToIPFS(finalFile);
        }

        const tx = await contract.createVault(
            seconds, 
            beneficiaryInput, 
            payloadType,
            storageMode,
            encryptedSecretHandle, 
            inputProof,
            cid
        );
        
        showToast("Processing", "Creating on-chain vault...", "hourglass_empty");
        const receipt = await tx.wait();
        
        if (keyToBackup) {
            localStorage.setItem(`vault_key_latest`, keyToBackup);
            // We use the new modal for this important info too, reusing revealedSecret state or a separate alert
            // For now, keep alert for Key Backup to ensure it's distinct
            alert(`⚠️ IMPORTANT: SAVE THIS KEY! ⚠️\n\nYou must share this key with the beneficiary manually. The contract does not store it.\n\nKEY: ${keyToBackup}`);
        }

        showToast("Success", "Vault Created.", "lock");
        setView('vaults');
        fetchMyVaults();

    } catch (e: any) {
        console.error(e);
        showToast("Error", e.reason || e.message || "Tx Failed", "error");
        setIsFHELoading(false);
    } finally {
        setIsLoading(false);
    }
  };

  const pingVault = async (vaultId: number) => {
    if (!contract) return;
    try {
        const tx = await contract.ping(vaultId);
        showToast("Sending Heartbeat", "Confirming life signs...", "ecg_heart");
        await tx.wait();
        showToast("Pulse Confirmed", "Timer reset successfully.", "check_circle");
        fetchMyVaults();
    } catch (e) {
        showToast("Error", "Ping failed.", "error");
    }
  };

  const claimVault = async (ownerAddr: string, vaultId: number) => {
    if (!contract) return;
    try {
        const tx = await contract.claim(ownerAddr, vaultId);
        showToast("Claiming", "Attempting to unlock vault...", "key");
        await tx.wait();
        showToast("Success", "Vault claimed! You can now view the secret.", "lock_open");
        fetchBeneficiaryVaults();
    } catch (e: any) {
        console.error(e);
        showToast("Error", "Claim failed (Time not elapsed?)", "error");
    }
  };

  const viewSecret = async (ownerAddr: string, vaultId: number, storageMode: number, pType: number) => {
      if (!contract || !account || !signer) {
          showToast("Error", "Wallet or contract not connected", "error");
          return;
      }
      
      try {
          if (storageMode === StorageMode.ONCHAIN_FHE) {
              if (!fhevmInstance) {
                  showToast("Error", "FHEVM not ready", "error");
                  return;
              }
              // ON-CHAIN DECRYPTION
              showToast("Fetching", "Getting encrypted data...", "cloud_download");
              const ciphertextHandle = await contract.getSecret(ownerAddr, vaultId);
              
              if (!ciphertextHandle || ciphertextHandle === ethers.ZeroHash || ciphertextHandle === "0x") {
                  throw new Error("No encrypted data found");
              }

              const keypair = fhevmInstance.generateKeypair();
              const handleContractPairs = [{
                  handle: ciphertextHandle,
                  contractAddress: CONTRACT_ADDRESS
              }];
              
              const eip712 = fhevmInstance.createEIP712(
                  keypair.publicKey,
                  [CONTRACT_ADDRESS]
              );
              
              showToast("Sign Required", "Please sign to decrypt", "draw");
              const signature = await signer.signTypedData(
                  eip712.domain,
                  { UserDecryptRequestVerification: eip712.types.UserDecryptRequestVerification },
                  eip712.message
              );

              showToast("Decrypting", "Requesting from Zama gateway...", "sync");
              
              // This can also be slow, show loader
              setIsFHELoading(true);
              
              const result = await fhevmInstance.userDecrypt(
                  handleContractPairs,
                  keypair.privateKey,
                  keypair.publicKey,
                  signature.replace("0x", ""),
                  [CONTRACT_ADDRESS],
                  account
              );
              
              setIsFHELoading(false);

              const decryptedValue = result[ciphertextHandle];
              let resultStr = decryptedValue.toString();
              
              try {
                  const bigIntValue = BigInt(resultStr);
                  if (bigIntValue > 0) {
                      const hex = "0x" + bigIntValue.toString(16);
                      const paddedHex = hex.length % 2 === 0 ? hex : "0x0" + hex.slice(2);
                      const decodedStr = ethers.toUtf8String(paddedHex);
                      resultStr = decodedStr.replace(/\0/g, '').trim();
                  }
              } catch (e) {
                  console.log("⚠️ UTF-8 conversion failed, showing raw value");
              }

              // Show nice modal instead of alert
              setRevealedSecret(resultStr);

          } else {
              // OFF-CHAIN IPFS
              showToast("Fetching", "Getting CID from contract...", "cloud_download");
              const cid = await contract.getCID(ownerAddr, vaultId);
              
              showToast("Downloading", "Fetching from IPFS...", "cloud");
              const blob = await fetchFromIPFS(cid);
              const text = await blob.text(); 
              
              try {
                  const payload = JSON.parse(text);
                  let importedKey: CryptoKey;
                  let keyStr = "";

                  // 1. Try to find key in localStorage
                  const storedKey = localStorage.getItem(`vault_key_latest`); 
                  
                  // 2. Prompt user
                  keyStr = prompt("🔐 DECRYPTION KEY REQUIRED\n\nPlease enter the decryption key shared by the owner:", storedKey || "") || "";
                  
                  if (!keyStr) {
                      alert("Decryption cancelled. Key is required.");
                      return;
                  }

                  try {
                      importedKey = await importKey(keyStr);
                  } catch(err) {
                      alert("Invalid Key Format");
                      return;
                  }

                  if (payload.iv && payload.data) {
                      showToast("Decrypting", "Decrypting content...", "lock_open");
                      
                      const iv = base64ToArrayBuffer(payload.iv);
                      
                      const res = await fetch(payload.data);
                      const encryptedBlob = await res.blob();
                      
                      const decryptedBlob = await decryptFile(encryptedBlob, importedKey, iv);
                      
                      if (payload.type === 'text/plain' || pType === PayloadType.TEXT) {
                          const decryptedText = await decryptedBlob.text();
                          setRevealedSecret(decryptedText);
                      } else {
                          // Download file
                          const url = URL.createObjectURL(decryptedBlob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = payload.name || "decrypted_file";
                          document.body.appendChild(a);
                          a.click();
                          document.body.removeChild(a);
                          URL.revokeObjectURL(url);
                          showToast("Downloaded", "File decrypted and downloaded", "download");
                      }
                  } else {
                      alert("Invalid Payload Format");
                  }
              } catch(e) {
                  alert(`🔓 RAW CONTENT (Failed to parse JSON):\n\n${text}`);
              }
          }
          
      } catch (e: any) {
          console.error("❌ View Error:", e);
          setIsFHELoading(false);
          showToast("Error", e.message || "Failed to view secret", "error");
      }
  };

  const copyToClipboard = () => {
      if (revealedSecret) {
          navigator.clipboard.writeText(revealedSecret);
          showToast("Copied", "Secret copied to clipboard", "content_copy");
      }
  };

  // --- DATA FETCHING ---
  const fetchMyVaults = async () => {
      if (!contract || !account) return;
      try {
          const ids = await contract.getOwnerVaults(account);
          const loadedVaults: VaultData[] = [];
          
          for (const id of ids) {
              const details = await contract.getVaultDetails(account, id);
              loadedVaults.push({
                  id: Number(id),
                  owner: account,
                  heartbeat: Number(details[0]),
                  lastPing: Number(details[1]),
                  beneficiary: details[2],
                  claimed: details[3],
                  status: 'active',
                  payloadType: Number(details[5]),
                  storageMode: Number(details[6])
              });
          }
          setMyVaults(loadedVaults);
      } catch (e) { console.error(e); }
  };

  const fetchBeneficiaryVaults = async () => {
      if (!contract) return;
      try {
          const result = await contract.getMyBeneficiaryVaults();
          const owners = result[0];
          const ids = result[1];
          
          const loadedVaults: VaultData[] = [];
          
          for (let i = 0; i < owners.length; i++) {
              const owner = owners[i];
              const id = ids[i];
              try {
                  const d = await contract.getVaultDetails(owner, id);
                  loadedVaults.push({
                      id: Number(id),
                      owner: owner,
                      heartbeat: Number(d[0]),
                      lastPing: Number(d[1]),
                      beneficiary: d[2],
                      claimed: d[3],
                      status: 'active',
                      payloadType: Number(d[5]),
                      storageMode: Number(d[6])
                  });
              } catch(e) {}
          }
          setWatchedVaults(loadedVaults);
      } catch (e) { console.error(e); }
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
      if (now > v.lastPing + v.heartbeat) return { text: "UNLOCKED", color: "bg-red-500", active: false };
      return { text: "SECURE", color: "bg-green-500", active: true };
  };

  // --- RENDER ---
  return (
    <>
      <div className="grid-bg"></div>
      
      {/* INITIAL LOAD SCREEN */}
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

      {/* CUSTOM FHE LOADER OVERLAY */}
      {isFHELoading && (
        <div className="fixed inset-0 z-[9999] bg-black/80 backdrop-blur-md flex flex-col justify-center items-center text-white animate-fade-in">
            <div className="loader-3d-cube mb-8"></div>
            <h3 className="text-2xl font-bold tracking-tight mb-2">Generating Zero Knowledge Proof</h3>
            <p className="text-gray-400 font-mono text-sm animate-pulse">This operation is compute intensive. Please wait...</p>
        </div>
      )}

      {/* REVEALED SECRET MODAL */}
      {revealedSecret && (
          <div className="secret-modal-overlay" onClick={() => setRevealedSecret(null)}>
              <div className="secret-modal" onClick={e => e.stopPropagation()}>
                  <div className="flex justify-between items-center mb-6">
                      <div className="flex items-center gap-3">
                          <span className="material-symbols-outlined text-2xl text-green-500">lock_open</span>
                          <h3 className="text-2xl font-bold">Secret Decrypted</h3>
                      </div>
                      <button onClick={() => setRevealedSecret(null)} className="w-8 h-8 flex items-center justify-center rounded-full hover:bg-gray-100 transition-colors">
                          <span className="material-symbols-outlined">close</span>
                      </button>
                  </div>
                  
                  <div className="text-sm text-gray-500 font-bold uppercase tracking-wider mb-2">Payload Content</div>
                  <div className="secret-content-box">
                      {revealedSecret}
                  </div>

                  <div className="flex gap-3">
                      <button onClick={copyToClipboard} className="flex-1 py-3 bg-black text-white rounded-xl font-bold hover:bg-zyellow hover:text-black transition-colors flex items-center justify-center gap-2">
                          <span className="material-symbols-outlined text-sm">content_copy</span> Copy
                      </button>
                      <button onClick={() => setRevealedSecret(null)} className="flex-1 py-3 bg-gray-100 text-black rounded-xl font-bold hover:bg-gray-200 transition-colors">
                          Close
                      </button>
                  </div>
              </div>
          </div>
      )}

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
                  <button onClick={authenticated ? undefined : handleConnect} className="btn-core bg-white border border-black text-black px-6 py-2.5 font-bold text-xs uppercase tracking-wider flex items-center gap-2 hover:bg-black hover:text-white transition-all shadow-md overflow-hidden">
                      <span className="relative z-10 flex items-center gap-2">
                          <span className="material-symbols-outlined text-base">wallet</span>
                          <span>{account ? `${account.substring(0,6)}...` : "Connect Wallet"}</span>
                      </span>
                      <div className="absolute inset-0 bg-zyellow translate-y-full group-hover:translate-y-0 transition-transform duration-300"></div>
                  </button>
                  {authenticated && (
                      <div className="absolute top-full right-0 mt-2 w-48 bg-white border border-gray-200 rounded-xl shadow-xl overflow-hidden hidden group-hover/wallet:block animate-fade-in-up">
                          <button onClick={() => { logout(); setView('hero'); setAccount(null); showToast("Disconnected", "Wallet disconnected", "link_off"); }} className="w-full text-left px-4 py-3 text-xs font-bold hover:bg-red-50 hover:text-red-600 transition-colors flex items-center gap-2">
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
                  <button onClick={() => { handleConnect(); }} className="btn-core bg-black text-white px-8 py-4 rounded-full font-bold text-sm shadow-xl hover:shadow-2xl hover:scale-105 flex items-center gap-3 transition-all shimmer-trigger">
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
                        <button onClick={() => { setView('vaults'); fetchMyVaults(); }} className={`px-8 py-2.5 rounded-full text-xs font-bold transition-all ${view === 'vaults' ? 'bg-black text-white shadow-lg' : 'text-gray-500 hover:text-black'}`}>MY VAULTS</button>
                        <button onClick={() => { setView('claim'); fetchBeneficiaryVaults(); }} className={`px-8 py-2.5 rounded-full text-xs font-bold transition-all ${view === 'claim' ? 'bg-black text-white shadow-lg' : 'text-gray-500 hover:text-black'}`}>CLAIM</button>
                    </div>
                </div>

                {view === 'create' && (
                    <div className="grid lg:grid-cols-12 gap-8 items-start animate-fade-in-up">
                        <div className="lg:col-span-7 glass-panel rounded-[2rem] p-8 md:p-12 relative overflow-hidden">
                            <h2 className="text-3xl font-bold mb-8 flex items-center gap-3">
                                <span className="w-2 h-8 bg-black"></span> Configure Vault
                            </h2>
                            <div className="space-y-6">
                                {/* Storage Mode Selection */}
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase">Storage Mode</label>
                                    <div className="flex gap-4 mb-4">
                                        <div onClick={() => { if(payloadType !== PayloadType.FILE) setStorageMode(StorageMode.ONCHAIN_FHE); }} 
                                             className={`flex-1 cursor-pointer border-2 rounded-xl p-4 flex flex-col items-center gap-2 transition-all ${storageMode===StorageMode.ONCHAIN_FHE ? 'border-black bg-gray-50' : 'border-gray-200 hover:bg-gray-50'} ${payloadType === PayloadType.FILE ? 'opacity-50 cursor-not-allowed' : ''}`}>
                                            <span className="material-symbols-outlined">enhanced_encryption</span>
                                            <span className="text-xs font-bold">On-Chain FHE</span>
                                        </div>
                                        <div onClick={() => setStorageMode(StorageMode.OFFCHAIN_IPFS)} 
                                             className={`flex-1 cursor-pointer border-2 rounded-xl p-4 flex flex-col items-center gap-2 transition-all ${storageMode===StorageMode.OFFCHAIN_IPFS ? 'border-black bg-gray-50' : 'border-gray-200 hover:bg-gray-50'}`}>
                                            <span className="material-symbols-outlined">cloud_queue</span>
                                            <span className="text-xs font-bold">Off-Chain IPFS</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase">Payload Type</label>
                                    <div className="flex gap-4 mb-4">
                                        <div onClick={() => setPayloadType(PayloadType.TEXT)} className={`flex-1 cursor-pointer border-2 rounded-xl p-4 flex flex-col items-center gap-2 transition-all ${payloadType===PayloadType.TEXT ? 'border-black bg-gray-50' : 'border-gray-200 hover:bg-gray-50'}`}>
                                            <span className="material-symbols-outlined">short_text</span>
                                            <span className="text-xs font-bold">Text</span>
                                        </div>
                                        <div onClick={() => { setPayloadType(PayloadType.FILE); setStorageMode(StorageMode.OFFCHAIN_IPFS); }} className={`flex-1 cursor-pointer border-2 rounded-xl p-4 flex flex-col items-center gap-2 transition-all ${payloadType===PayloadType.FILE ? 'border-black bg-gray-50' : 'border-gray-200 hover:bg-gray-50'}`}>
                                            <span className="material-symbols-outlined">attach_file</span>
                                            <span className="text-xs font-bold">File</span>
                                        </div>
                                    </div>
                                    
                                    {payloadType === PayloadType.TEXT ? (
                                        <textarea value={secretText} onChange={(e) => setSecretText(e.target.value)} className="z-input h-32 resize-none" placeholder="Enter private keys or secret message..."></textarea>
                                    ) : (
                                        <div className="relative h-32 border-2 border-dashed border-gray-300 rounded-xl bg-gray-50 hover:bg-white transition-colors flex flex-col items-center justify-center text-gray-400">
                                            <input type="file" className="absolute inset-0 opacity-0 cursor-pointer" onChange={(e) => { 
                                                if(e.target.files?.[0]) {
                                                    setFile(e.target.files[0]);
                                                    setFileMeta(e.target.files[0].name); 
                                                }
                                            }} />
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
                                            {isLoading ? (isFHELoading ? "Processing..." : "Confirming...") : "Lock Vault"}
                                        </div>
                                        <div className="text-xs text-gray-400 font-mono">
                                            {isFHELoading ? "Encrypting with FHE" : "0.02 ETH GAS FEE"}
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
                        <h2 className="text-4xl font-bold mb-8">Your Vaults</h2>
                        {myVaults.length === 0 ? (
                             <div className="text-center py-20">
                                <div className="w-20 h-20 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                    <span className="material-symbols-outlined text-3xl text-gray-400">lock_open</span>
                                </div>
                                <h3 className="font-bold text-gray-400">No active vaults found.</h3>
                                <button className="mt-4 text-xs font-bold underline" onClick={() => setView('create')}>Create one</button>
                            </div>
                        ) : (
                            <div className="grid md:grid-cols-2 gap-6">
                                {myVaults.map((vault) => (
                                    <div key={vault.id} className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm flex flex-col gap-6 hover:shadow-lg transition-all">
                                        <div className="flex justify-between items-start">
                                            <div>
                                                <h3 className="text-2xl font-bold">VAULT #{vault.id}</h3>
                                                <p className="text-xs text-gray-400 font-mono">BENEFICIARY: {vault.beneficiary.substring(0,6)}...</p>
                                            </div>
                                            <div className="flex gap-2">
                                                <span className="text-xl" title={vault.payloadType === PayloadType.TEXT ? "Text" : "File"}>
                                                    {vault.payloadType === PayloadType.TEXT ? "📝" : "📎"}
                                                </span>
                                                <span className="text-xl" title={vault.storageMode === StorageMode.ONCHAIN_FHE ? "On-Chain FHE" : "Off-Chain IPFS"}>
                                                    {vault.storageMode === StorageMode.ONCHAIN_FHE ? "🔐" : "☁️"}
                                                </span>
                                            </div>
                                        </div>
                                        <div className={`px-3 py-1 text-white text-xs font-bold rounded-full w-fit ${getStatus(vault).color}`}>
                                            {getStatus(vault).text}
                                        </div>
                                        <div className="space-y-2">
                                            <div className="w-full bg-gray-100 rounded-full h-3 overflow-hidden relative">
                                                <div 
                                                    className="h-full bg-black transition-all duration-1000 ease-linear relative overflow-hidden" 
                                                    style={{width: `${getProgressWidth(vault.lastPing, vault.heartbeat)}%`}}
                                                >
                                                    <div className="absolute inset-0 bg-white/20 animate-pulse-fast"></div>
                                                </div>
                                            </div>
                                            <div className="flex justify-between text-xs font-mono">
                                                <span className="text-gray-400 font-bold">TTL</span>
                                                <span className="font-bold text-lg">{formatTimeRemaining(vault.lastPing, vault.heartbeat)}</span>
                                            </div>
                                        </div>
                                        <button onClick={() => pingVault(vault.id)} className="w-full py-4 bg-zyellow hover:bg-black hover:text-white transition-colors text-black font-bold rounded-xl flex items-center justify-center gap-2">
                                             <span className="material-symbols-outlined animate-pulse">ecg_heart</span> PING
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}

                {view === 'claim' && (
                    <div className="glass-panel rounded-[2.5rem] min-h-[400px] p-8">
                         <div className="flex justify-between items-center mb-8">
                            <h2 className="text-4xl font-bold">Claim Vaults</h2>
                            <button onClick={fetchBeneficiaryVaults} className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center hover:bg-black hover:text-white transition-all"><span className="material-symbols-outlined">refresh</span></button>
                        </div>
                        <div className="grid md:grid-cols-2 gap-6">
                            {watchedVaults.map((v, i) => (
                                <div key={i} className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm hover:shadow-lg transition-all">
                                    <div className="mb-4">
                                        <div className="flex justify-between">
                                            <h3 className="text-lg font-bold truncate">Owner: {v.owner.substring(0,6)}...</h3>
                                            <div className="flex gap-1">
                                                <span>{v.payloadType === PayloadType.TEXT ? "📝" : "📎"}</span>
                                                <span>{v.storageMode === StorageMode.ONCHAIN_FHE ? "🔐" : "☁️"}</span>
                                            </div>
                                        </div>
                                        <h4 className="text-sm font-mono text-gray-500">Vault #{v.id}</h4>
                                        <div className="flex items-center gap-2 mt-2">
                                            <span className={`w-2 h-2 rounded-full ${getStatus(v).color}`}></span>
                                            <span className="text-xs font-bold text-gray-500">{getStatus(v).text}</span>
                                        </div>
                                    </div>
                                    <div className="flex gap-2">
                                        {!v.claimed && getStatus(v).active === false ? (
                                             <button onClick={() => claimVault(v.owner, v.id)} className="flex-1 py-3 bg-black text-white font-bold rounded-xl hover:bg-zyellow hover:text-black transition-colors">CLAIM</button>
                                        ) : v.claimed ? (
                                            <button onClick={() => viewSecret(v.owner, v.id, v.storageMode, v.payloadType)} className="flex-1 py-3 bg-gray-900 text-white font-bold rounded-xl hover:bg-gray-800 transition-colors flex items-center justify-center gap-2">
                                                <span className="material-symbols-outlined text-sm">visibility</span> VIEW SECRET
                                            </button>
                                        ) : (
                                            <button disabled className="flex-1 py-3 bg-gray-100 text-gray-400 font-bold rounded-xl cursor-not-allowed">LOCKED</button>
                                        )}
                                    </div>
                                </div>
                            ))}
                            {watchedVaults.length === 0 && (
                                <div className="col-span-full text-center text-gray-400 text-sm py-10">You are not a beneficiary for any vaults yet.</div>
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

export default function App() {
    return (
        <PrivyProvider
            appId={PRIVY_APP_ID}
            config={{
                loginMethods: ['wallet', 'email', 'sms'],
                appearance: {
                    theme: 'light',
                    accentColor: '#676FFF',
                },
            }}
        >
            <InnerApp />
        </PrivyProvider>
    );
}
