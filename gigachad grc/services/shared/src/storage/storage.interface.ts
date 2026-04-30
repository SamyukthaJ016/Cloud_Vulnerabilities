import { Readable } from 'stream';

export interface StorageProvider {
  /**
   * Upload a file to storage
   * @param file - File buffer or readable stream
   * @param path - Storage path (e.g., "evidence/org123/file.pdf")
   * @param options - Upload options
   * @returns Full storage path
   */
  upload(
    file: Buffer | Readable,
    path: string,
    options?: UploadOptions
  ): Promise<string>;

  /**
   * Download a file from storage
   * @param path - Storage path
   * @returns Readable stream of file contents
   */
  download(path: string): Promise<Readable>;

  /**
   * Delete a file from storage
   * @param path - Storage path
   */
  delete(path: string): Promise<void>;

  /**
   * Check if a file exists
   * @param path - Storage path
   */
  exists(path: string): Promise<boolean>;

  /**
   * Get a signed URL for temporary access (if supported)
   * @param path - Storage path
   * @param expiresIn - Expiration time in seconds
   */
  getSignedUrl(path: string, expiresIn?: number): Promise<string>;

  /**
   * Get file metadata
   * @param path - Storage path
   */
  getMetadata(path: string): Promise<FileMetadata | null>;

  /**
   * List files in a directory
   * @param prefix - Directory prefix
   */
  list(prefix: string): Promise<FileMetadata[]>;

  /**
   * Copy a file to a new location
   * @param sourcePath - Source path
   * @param destPath - Destination path
   */
  copy(sourcePath: string, destPath: string): Promise<string>;
}

export interface UploadOptions {
  contentType?: string;
  metadata?: Record<string, string>;
  acl?: 'private' | 'public-read';
}

export interface FileMetadata {
  path: string;
  size: number;
  contentType?: string;
  lastModified: Date;
  etag?: string;
  metadata?: Record<string, string>;
}

export type StorageType = 'local' | 'minio' | 's3' | 'azure';

export interface StorageConfig {
  type: StorageType;
  
  // Local storage options
  localPath?: string;
  localBaseUrl?: string;
  
  // S3/RustFS options (S3-compatible)
  endpoint?: string;
  port?: number;
  useSSL?: boolean;
  accessKey?: string;
  secretKey?: string;
  bucket?: string;
  region?: string;
  
  // Azure Blob Storage options
  azureConnectionString?: string;
  azureAccountName?: string;
  azureAccountKey?: string;
  azureSasToken?: string;
  azureContainerName?: string;
}



