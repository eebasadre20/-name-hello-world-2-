
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('managers')
export class Manager {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string; // This should be hashed

  @Column({ nullable: true })
  confirmed_at: Date;

  @Column({ nullable: true })
  locked_at: Date;

  @Column({ default: 0 })
  failed_attempts: number;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}
