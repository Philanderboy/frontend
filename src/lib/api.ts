// Heliobond - project data API client.
//
// Reads from NEXT_PUBLIC_API_URL when set (GET /projects, GET /projects/:id).
// Falls back to local mock data when the env var is absent or the request fails,
// so the click-through always works without a running backend.

import { HB_DATA, type Project } from '../data'
import { PROJECT_DETAILS, type ProjectDetail } from '../data/projectDetails'

const API_URL = process.env.NEXT_PUBLIC_API_URL

export interface ProjectWithDetail {
  project: Project
  detail: ProjectDetail
}

export async function getProjects(): Promise<Project[]> {
  if (!API_URL) return HB_DATA.projects
  try {
    const res = await fetch(`${API_URL}/projects`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return (await res.json()) as Project[]
  } catch {
    console.warn('[api] GET /projects failed - using mock data')
    return HB_DATA.projects
  }
}

export async function getProject(id: number): Promise<ProjectWithDetail | null> {
  const mockProject = HB_DATA.projects.find((p) => p.id === id)
  const mockDetail = PROJECT_DETAILS[id]

  if (!API_URL) {
    if (!mockProject || !mockDetail) return null
    return { project: mockProject, detail: mockDetail }
  }

  try {
    const res = await fetch(`${API_URL}/projects/${id}`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return (await res.json()) as ProjectWithDetail
  } catch {
    console.warn(`[api] GET /projects/${id} failed - using mock data`)
    if (!mockProject || !mockDetail) return null
    return { project: mockProject, detail: mockDetail }
  }
}

/**
 * Performs biometric login (Face ID / Touch ID) using the WebAuthn API.
 * Returns true if the user successfully authenticates, false otherwise.
 * This is a client-side implementation; the actual verification should happen
 * with a backend challenge, but for now we generate a random challenge locally.
 */
export async function biometricLogin(): Promise<boolean> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential || !navigator.credentials) {
    console.warn('[api] Biometric login not supported on this device/browser')
    return false
  }

  try {
    // Generate a random challenge (in production, this would come from the server)
    const challenge = new Uint8Array(32)
    crypto.getRandomValues(challenge)
  
    // Request a credential from the authenticator
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: window.location.hostname,
        allowCredentials: [],
        userVerification: 'required',
      },
    })
  
    return Boolean(credential)
  } catch (error) {
    console.warn('[api] biometric login failed:', error)
    return false
  }
}
